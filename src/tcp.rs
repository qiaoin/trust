use bitflags::bitflags;
use std::{
    collections::{BTreeMap, VecDeque},
    io, time,
};

bitflags! {
    pub(crate) struct Available: u8 {
        const READ = 0b00000001;
        const WRITE = 0b00000010;
    }
}

#[derive(Debug)]
enum State {
    // Closed,
    // Listen,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            State::SynRcvd => false,
            State::Estab | State::FinWait1 | State::FinWait2 | State::TimeWait => true,
        }
    }
}

// Transmission Control Block
pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
    timers: Timers,

    pub(crate) incoming: VecDeque<u8>,
    pub(crate) unacked: VecDeque<u8>,

    pub(crate) closed: bool,
    closed_at: Option<u32>,
}

struct Timers {
    send_times: BTreeMap<u32, time::Instant>,
    srtt: f64,
}

impl Connection {
    pub(crate) fn is_rcv_closed(&self) -> bool {
        eprintln!("ask if closed when in {:?}", self.state);
        if let State::TimeWait = self.state {
            // TODO: any state after rcvd FIN, so also CLOSE-WAIT, LAST-ACK, CLOSED, CLOSING
            true
        } else {
            false
        }
    }

    fn availability(&self) -> Available {
        let mut a = Available::empty();
        eprintln!(
            "computing availability, where {:?}, {:?}",
            self.is_rcv_closed(),
            self.incoming.is_empty()
        );
        if self.is_rcv_closed() || !self.incoming.is_empty() {
            a |= Available::READ;
        }

        // TODO: take into account self.state
        // TODO: set Available::WRITE
        a
    }
}

/// State of Send Sequence Space (RFC 793 S3.2 Figure 4)
/// ```
///      1         2          3          4
/// ----------|----------|----------|----------
///        SND.UNA    SND.NXT    SND.UNA
///                             +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
/// ```
struct SendSequenceSpace {
    /// send unacknowledged
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: u32,
    /// segment acknowledgment number used for last window update
    wl2: u32,
    /// initial send sequence number
    iss: u32,
}

/// State of Receive Sequence Space (RFC 793 S3.2 Figure 5)
/// ```
///      1          2          3
/// ----------|----------|----------
///        RCV.NXT    RCV.NXT
///                  +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
/// ```
struct RecvSequenceSpace {
    /// receive next
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

// 对于不同的状态，有不同的表现，因此就没有 Default
// impl Default for Connection {
//     fn default() -> Self {
//         // State::Closed
//         Connection {
//             state: State::Listen,
//         }
//     }
// }

impl Connection {
    // 前置条件：Listen State
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        let buf = [0u8; 1500];
        if !tcph.syn() {
            // only expected SYN package
            return Ok(None);
        }

        let iss = 0;
        let wnd = 1024;
        let mut c = Connection {
            timers: Timers {
                send_times: Default::default(),
                srtt: time::Duration::from_secs(1 * 60).as_secs_f64(),
            },
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss,
                wnd,

                up: false,
                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                nxt: tcph.sequence_number() + 1,
                wnd: tcph.window_size(),
                irs: tcph.sequence_number(),

                up: false,
            },
            ip: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpTrafficClass::Tcp,
                [
                    iph.destination()[0],
                    iph.destination()[1],
                    iph.destination()[2],
                    iph.destination()[3],
                ],
                [
                    iph.source()[0],
                    iph.source()[1],
                    iph.source()[2],
                    iph.source()[3],
                ],
            ),
            tcp: etherparse::TcpHeader::new(tcph.destination_port(), tcph.source_port(), iss, wnd),

            incoming: Default::default(),
            unacked: Default::default(),

            closed: false,
            closed_at: None,
        };

        // need to start establishing a connection
        c.tcp.ack = true;
        c.tcp.syn = true;

        c.write(nic, c.send.nxt, 0)?;
        Ok(Some(c))
    }

    fn write(&mut self, nic: &mut tun_tap::Iface, seq: u32, mut limit: usize) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledgment_number = self.recv.nxt;

        // TODO: return +1 for SYN/FIN
        println!(
            "write(ack: {}, seq: {}, limit: {}) syn {:?} fin {:?}",
            self.recv.nxt - self.recv.irs,
            seq,
            limit,
            self.tcp.syn,
            self.tcp.fin,
        );

        // we want self.unacked[nunacked..]
        // we need to special-case the two "virtual" bytes SYN and FIN
        let mut offset = seq.wrapping_sub(self.send.una) as usize;
        if let Some(close_at) = self.closed_at {
            if seq == close_at.wrapping_sub(1) {
                // trying to write the following FIN
                offset = 0;
                limit = 0;
            }
        }

        println!(
            "using offset {} base {} in {:?}",
            offset,
            self.send.una,
            self.unacked.as_slices()
        );

        let (mut head, mut tail) = self.unacked.as_slices();
        if head.len() >= offset {
            head = &head[offset..];
        } else {
            let skipped = head.len();
            head = &[];
            tail = &tail[(offset - skipped)..];
        }

        let max_data = std::cmp::min(limit, head.len() + tail.len());
        let size = std::cmp::min(
            buf.len(),
            self.tcp.header_len() as usize + self.ip.header_len() as usize + max_data,
        );

        self.ip
            .set_payload_len(size - self.ip.header_len() as usize);

        // the kernel is nice and does this for us
        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &[])
            .expect("fail to compute checksum");

        // write out the headers
        use std::io::Write;
        let mut unwritten = &mut buf[..];
        self.ip.write(&mut unwritten);
        self.tcp.write(&mut unwritten);

        let payload_bytes = {
            let mut written = 0;
            let mut limit = max_data;

            // first, write as much as we can from head
            let p1l = std::cmp::min(limit, head.len());
            written += unwritten.write(&head[..p1l])?;
            limit -= written;

            // then, write more (if we can) from tail
            let p2l = std::cmp::min(limit, tail.len());
            written += unwritten.write(&tail[..p2l])?;

            written
        };
        let unwritten = unwritten.len();
        let mut next_seq = seq.wrapping_add(payload_bytes as u32);
        if self.tcp.syn {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.fin = false;
        }

        if wrapping_lt(self.send.nxt, next_seq) {
            self.send.nxt = next_seq;
        }

        self.timers.send_times.insert(seq, time::Instant::now());

        nic.send(&buf[..buf.len() - unwritten])?;
        Ok(payload_bytes)
    }

    fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        self.tcp.rst = true;
        // TODO: fix sequence number here
        // RFC 793 Page 35
        // If the incoming segment has an ACK field, the reset takes its
        // sequence number from the ACK field of the segment, otherwise the
        // reset has sequence number zero and the ACK field is set to the sum
        // of the sequence number and segment length of the incoming segment.
        // The connection remains in the same state.
        //
        // TODO: handle synchronized RST
        // 3.  If the connection is in a synchronized state (ESTABLISHED,
        // FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT),
        // any unacceptable segment (out of window sequence number or
        // unacceptible acknowledgment number) must elicit only an empty
        // acknowledgment segment containing the current send-sequence number
        // and an acknowledgment indicating the next sequence number expected
        // to be received, and the connection remains in the same state.
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;

        self.write(nic, self.send.nxt, 0)?;
        Ok(())
    }

    pub(crate) fn on_tick<'a>(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        // decide if it need to send something, send it
        let nunacked = self.send.nxt.wrapping_sub(self.send.una);
        let unsent = self.unacked.len() as u32 - nunacked;

        let waited_for = self
            .timers
            .send_times
            .range(self.send.una..)
            .next()
            .map(|t| t.1.elapsed());

        let should_retransmit = if let Some(waited_for) = waited_for {
            waited_for > time::Duration::from_secs(1)
                && waited_for.as_secs_f64() > 1.5 * self.timers.srtt
        } else {
            false
        };

        if should_retransmit {
            // we should retransmit things!
            let resend = std::cmp::min(self.unacked.len() as u32, self.send.wnd as u32);
            if resend < self.send.wnd as u32 && self.closed {
                // can we include the FIN?
                self.tcp.fin = true;
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
            }
            self.write(nic, self.send.una, resend as usize)?;
        } else {
            // we should send new data if we have new data and space in the window
            if unsent == 0 && self.closed_at.is_some() {
                return Ok(());
            }

            let allowed = self.send.wnd as u32 - nunacked;
            if allowed == 0 {
                return Ok(());
            }

            let send = std::cmp::min(unsent, allowed);
            if send < allowed && self.closed && self.closed_at.is_none() {
                // send the FIN
                self.tcp.fin = true;
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
            }

            self.write(nic, self.send.nxt, send as usize)?;
        }

        // if FIN, enter FIN-WAIT-1
        Ok(())
    }

    pub(crate) fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Available> {
        // first, check that sequence numbers are valid (RFC 793 S3.3)
        //
        // valid segment check. okey if it acks at least one byte, which means that at least
        // one of the following is true:
        //   - RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        //   - RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        //
        let seqn = tcph.sequence_number();
        let mut slen = data.len() as u32;
        if tcph.fin() || tcph.syn() {
            slen += 1;
        }
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        let okay = if slen == 0 {
            // zero-length segment has separate rules for acceptance
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    false
                } else {
                    true
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                false
            } else {
                true
            }
        } else {
            if self.recv.wnd == 0 {
                false
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen - 1),
                    wend,
                )
            {
                false
            } else {
                true
            }
        };

        if !okay {
            eprintln!("NOT OKAY");
            self.write(nic, self.send.nxt, 0)?;
            return Ok(self.availability());
        }

        // TODO: make sure this get acked

        // RFC 793 Page 68 SEGMENT ARRIVES
        // TODO: if _not_ acceptable, send ACK
        // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

        if !tcph.ack() {
            eprintln!("NOT ACK");
            if tcph.syn() {
                // got SYN part of initial handshake
                assert!(data.is_empty());
                self.recv.nxt = seqn.wrapping_add(1);
            }
            return Ok(self.availability());
        }

        let ackn = tcph.acknowledgment_number();
        if let State::SynRcvd = self.state {
            if is_between_wrapped(
                self.send.una.wrapping_sub(1),
                ackn,
                self.send.nxt.wrapping_add(1),
            ) {
                // must have ACKed our SYN, since we detected at least one acked byte,
                // and we have only sent only one byte (the SYN)
                self.state = State::Estab;
            } else {
                // TODO: <SEQ=SEG.ACK><CTL=RST> Page 71
            }
        }

        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            if is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                // if !self.state.is_synchronized() {
                //     // RFC 793 S3.4 Page 35
                //     // according to Reset Generation, we should send a RST
                //     self.send_rst(nic)?;
                // }
                println!(
                    "ack for {} (last: {}); prune in {:?}",
                    ackn, self.send.una, self.unacked
                );
                if !self.unacked.is_empty() {
                    let nacked = self
                        .unacked
                        .drain(..ackn.wrapping_sub(self.send.una) as usize)
                        .count();

                    let una = self.send.una;
                    let srtt = &mut self.timers.srtt;
                    self.timers.send_times.retain(|&seq, sent| {
                        if is_between_wrapped(una, seq, ackn) {
                            *srtt = 0.8 * *srtt + (1.0 - 0.8) * sent.elapsed().as_secs_f64();
                            false
                        } else {
                            true
                        }
                    });
                }

                self.send.una = ackn;
            }
            // TODO: prune self.unacked
            // TODO: if self.unacked is empty, and wait flush, notify
            // TODO: update window

            // FIXME: we don't support Write yet, so immediately send EOF
            // if let State::Estab = self.state {
            //     // TODO: needs to be store in the retransmission queue!
            //     self.tcp.fin = true;
            //     // self.write(nic, self.send.nxt, 0)?;
            //     self.state = State::FinWait1;
            // }
        }

        if let State::FinWait1 = self.state {
            if self.send.una == self.send.iss + 2 {
                // our FIN has been ACKed

                // must have ACKed our FIN, since we detected at least one acked byte,
                // and we have only sent only one byte (the FIN)
                self.state = State::FinWait2;
            }
        }

        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            // TODO: only read stuff we haven't read
            let mut unread_data_at = (self.recv.nxt - seqn) as usize;
            if unread_data_at > data.len() {
                // we must have received a re-transmitted FIN that we have already seen,
                // nxt points to beyond the FIN, but the FIN is not in data!
                assert_eq!(unread_data_at, data.len() + 1);
                unread_data_at = 0;
            }
            self.incoming.extend(&data[unread_data_at..]);

            // Once the TCP takes responsibility for the data it advances
            // RCV.NXT over the data accepted, and adjusts RCV.WND as
            // apporopriate to the current buffer availability.  The total of
            // RCV.NXT and RCV.WND should not be reduced.
            self.recv.nxt = seqn
                .wrapping_add(data.len() as u32)
                .wrapping_add(if tcph.fin() { 1 } else { 0 });

            // Send an acknowledgment of the form: <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            // TODO: maybe just tick to piggyback ack on data
            self.write(nic, self.send.nxt, 0)?;
        }

        if tcph.fin() {
            eprintln!("IS FIN (in {:?})", self.state);
            if let State::FinWait2 = self.state {
                // we're done with the connection!
                if !tcph.fin() && !data.is_empty() {
                    unimplemented!();
                }

                self.write(nic, self.send.nxt, 0)?;
                self.state = State::TimeWait;
            }
        }

        Ok(self.availability())
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        match self.state {
            State::SynRcvd | State::Estab => {
                self.state = State::FinWait1;
            }
            State::FinWait1 | State::FinWait2 => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "already closing",
                ))
            }
        }
        Ok(())
    }
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // From RFC1323 - window scaling:
    //     TCP determines if a data segment is "old" or "new" by testing
    //     whether its sequence number is within 2**31 bytes of the left edge
    //     of the window, and if it is not, discarding the data as "old".  To
    //     insure that new data is never mistakenly considered old and vice-
    //     versa, the left edge of the sender's window has to be at most
    //     2**31 away from the right edge of the receiver's window.
    lhs.wrapping_sub(rhs) > 2 ^ 31
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}
