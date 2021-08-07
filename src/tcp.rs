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
/// 包含的状态都为被动打开（passive OPEN），也就是 server 端状态
/// 主动打开（active open）使用 nc/curl 来进行模拟测试，作为 client 端
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
    // (RFC 793 Page 32) 在 RESET 的时候使用，目前未实现 RESET
    fn is_synchronized(&self) -> bool {
        match *self {
            State::SynRcvd => false,
            State::Estab | State::FinWait1 | State::FinWait2 | State::TimeWait => true,
        }
    }
}

// Transmission Control Block
pub struct Connection {
    ///
    state: State,
    ///
    send: SendSequenceSpace,
    ///
    recv: RecvSequenceSpace,
    ///
    ip: etherparse::Ipv4Header,
    ///
    tcp: etherparse::TcpHeader,
    ///
    timers: Timers,

    ///
    pub(crate) incoming: VecDeque<u8>,
    ///
    pub(crate) unacked: VecDeque<u8>,

    ///
    pub(crate) closed: bool,
    ///
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

/// State of Send Sequence Space (RFC 793 S3.2 Figure 4 Page 20)
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

/// State of Receive Sequence Space (RFC 793 S3.2 Figure 5 Page 20)
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

impl Connection {
    /// server 已启动，处于 Listen State，Client 发起连接，API 等同 Unix Socket 接口
    ///
    /// Unix Socket 接口
    ///
    /// 前置条件：Listen State
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
    ) -> io::Result<Option<Self>> {
        // RFC 793 Page 65: Event processing - SEGMENT ARRIVES
        //   third check for a SYN
        if !tcph.syn() {
            // only expected SYN package
            return Ok(None);
        }

        // RFC 793 Page 27 - Initial Sequence Number Selection
        let iss = 0;
        let wnd = 1024;
        let mut c = Connection {
            timers: Timers {
                send_times: Default::default(),
                srtt: time::Duration::from_secs(1 * 60).as_secs_f64(),
            },
            state: State::SynRcvd,
            send: SendSequenceSpace {
                // RFC 793 Page 66
                // SND.NXT is set to ISS+1 and SND.UNA to ISS
                // SND.NXT = ISS+1, 在 write 中判断为 SYN 时，进行 +1
                iss,
                una: iss,
                nxt: iss,
                wnd,

                up: false,
                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                // RFC 793 Page 66
                // Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ
                nxt: tcph.sequence_number().wrapping_add(1),
                wnd: tcph.window_size(),
                irs: tcph.sequence_number(),

                up: false,
            },
            // 看一下 etherparse crate 文档
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
        // 接收到 SYN
        // 状态转移: LISTEN --> SYN-RECEIVED
        // 发送 SYN + ACK
        // RFC 793 Page 66
        // ISS should be selected and a SYN segment sent of the form:
        //   <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
        c.tcp.ack = true;
        c.tcp.syn = true;

        c.write(nic, c.send.nxt, 0)?;
        Ok(Some(c))
    }

    /// 发送数据到对端，由于我们实现的是 Server，因此这里是 Server 往 Client 写
    /// seq -- 发送端的序列号
    /// limit -- 期望发送的字节长度，实际发送的数据 <= limit
    fn write(&mut self, nic: &mut tun_tap::Iface, seq: u32, mut limit: usize) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        // RFC 793 Page 66
        // if the state is Listen then, s SYN segment sent of the form:
        //   <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
        self.tcp.sequence_number = seq;
        self.tcp.acknowledgment_number = self.recv.nxt;

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
        // TODO: close_at 是什么时候更新的呢？
        if let Some(close_at) = self.closed_at {
            if seq == close_at.wrapping_add(1) {
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

        // 由于使用了 VecDeque，为环形缓冲区，因此需要将 head 和 tail 进行分别判断
        // 看一看标准库 VecDeque 的 API 文档
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
            self.ip.header_len() as usize + self.tcp.header_len() as usize + max_data,
        );

        self.ip
            .set_payload_len(size - self.ip.header_len() as usize);

        // write out the headers and the payload
        use std::io::Write;
        let buf_len = buf.len();
        let mut unwritten = &mut buf[..];
        self.ip.write(&mut unwritten);
        let ip_header_ends_at = buf_len - unwritten.len();

        // postpone writing the tcp header because we need the payloads
        // as one contiguous slice to calculate the tcp checksum
        // 占位，保留 TCP header 的位置
        unwritten = &mut unwritten[self.tcp.header_len() as usize..];
        let tcp_header_ends_at = buf_len - unwritten.len();

        // write out the payload
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
        let payload_ends_at = buf_len - unwritten.len();

        // finally, we can calculate the tcp checksum and write out the tcp header
        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &buf[tcp_header_ends_at..payload_ends_at])
            .expect("fail to compute checksum");
        let mut tcp_header_buf = &mut buf[ip_header_ends_at..tcp_header_ends_at];
        self.tcp.write(&mut tcp_header_buf);

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

        nic.send(&buf[..payload_ends_at])?;
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
        // RFC 793 Page 37
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

    // TODO: on_tick 要解决什么问题？
    pub(crate) fn on_tick<'a>(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        // we have shutdown our write side and the other side acked, no need to (re)transmit anything
        if let State::FinWait2 | State::TimeWait = self.state {
            return Ok(());
        }

        // decide if it need to send something, send it
        let nunacked = self
            .closed_at
            .unwrap_or(self.send.nxt)
            .wrapping_sub(self.send.una);
        let unsent = self.unacked.len() as u32 - nunacked;

        let waited_for = self
            .timers
            .send_times
            .range(self.send.una..)
            .next()
            .map(|t| t.1.elapsed());

        // (RFC 793 Page 41) Retransmission Timeout
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

    // RFC 793 Page 69
    // SEGMENT ARRIVES, Otherwise, ...
    pub(crate) fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Available> {
        // first, check that sequence numbers are valid (RFC 793 S3.3 Page 25 - 26)
        //
        // valid segment check. okay if it acks at least one byte, which means that at least
        // one of the following is true:
        //   - RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        //   - RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        //
        // SEG.SEQ = first sequence number occupied by the incoming segment
        let seqn = tcph.sequence_number();

        // (RFC 793 Page 25)
        // SEG.LEN = the number of octets occupied by the data in the segment (counting SYN and FIN)
        let mut slen = data.len() as u32;
        if tcph.fin() || tcph.syn() {
            slen += 1;
        }

        // (RFC 793 Page 69, 变量定义在 Page 25)
        //
        // There are four cases for the acceptability test for an incoming
        // segment:
        //
        // Segment Receive  Test
        // Length  Window
        // ------- -------  -------------------------------------------
        //
        //    0       0     SEG.SEQ = RCV.NXT
        //
        //    0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        //
        //   >0       0     not acceptable
        //
        //   >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        //               or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND

        // (RFC 793 Page 25)
        // RCV.NXT+RCV.WND-1 = last sequence number expected on an incoming
        //     segment, and is the right or upper edge of the receive window
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        let okay = if slen == 0 {
            // zero-length segment has separate rules for acceptance
            if self.recv.wnd == 0 {
                if seqn == self.recv.nxt {
                    true
                } else {
                    false
                }
            } else if is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                true
            } else {
                false
            }
        } else {
            if self.recv.wnd == 0 {
                false
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen).wrapping_sub(1),
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
            // RFC 793 Page 69, first check ... 后半部分
            // If an incoming segment is not acceptable, an acknowledgment
            // should be sent in reply (unless the RST bit is set, if so drop
            // the segment and return):
            //
            //   <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            //
            // After sending the acknowledgment, drop the unacceptable segment
            // and return.
            self.write(nic, self.send.nxt, 0)?;
            return Ok(self.availability());
        }

        // RFC 793 Page 72, fifth check the ACK field
        // if the ACK bit is off drop the segment and return
        if !tcph.ack() {
            eprintln!("NOT ACK");
            // RFC 793 Page 71, fourt check the SYN bit
            //
            // TODO: 按照 RFC 的说明，这里接收到 SYN 是一个 error，为什么这里还需要这样进行处理呢？
            if tcph.syn() {
                // got SYN part of initial handshake
                assert!(data.is_empty());
                self.recv.nxt = seqn.wrapping_add(1);
            }
            return Ok(self.availability());
        }

        let ackn = tcph.acknowledgment_number();
        // RFC 793 Page 72, fifth check the ACK field
        //
        // SYN-RECEIVED STATE
        //   If SND.UNA =< SEG.ACK =< SND.NXT then enter ESTABLISHED state
        //   and continue processing.
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
                // TODO: <SEQ=SEG.ACK><CTL=RST> Page 72
            }
        }

        // ESTABLISHED STATE
        // FIN-WAIT-1 STATE - In addition to the processing for the ESTABLISHED state
        // FIN-WAIT-2 STATE
        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            // If SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK.
            if is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                println!(
                    "ack for {} (last: {}); prune in {:?}",
                    ackn, self.send.una, self.unacked
                );

                if !self.unacked.is_empty() {
                    // 删除已经 ack 的部分
                    let data_start = if self.send.una == self.send.iss {
                        // send.una hasn't been updated yet with ACK for our SYN, so data starts just beyond it
                        self.send.una.wrapping_add(1)
                    } else {
                        self.send.una
                    };
                    let acked_data_end =
                        std::cmp::min(ackn.wrapping_sub(data_start) as usize, self.unacked.len());
                    self.unacked.drain(..acked_data_end);

                    // TODO: 未理解这一部分内容
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

                // update SND.UNA <- SEG.ACK
                self.send.una = ackn;
            }

            // TODO: if self.unacked is empty, and wait flush, notify
            // TODO: update window
        }

        if let State::FinWait1 = self.state {
            if let Some(close_at) = self.closed_at {
                if self.send.una == close_at.wrapping_add(1) {
                    // our FIN has been ACKed

                    // must have ACKed our FIN, since we detected at least one acked byte,
                    // and we have only sent only one byte (the FIN)
                    self.state = State::FinWait2;
                }
            }
        }

        // RFC 793 Page 72, seventh process the segment text
        //
        // ESTABLISHED STATE
        // FIN-WAIT-1 STATE
        // FIN-WAIT-2 STATE
        if data.is_empty() {
            if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
                // Once in the ESTABLISHED state, it is possible to deliver segment
                // tex to user RECEIVE buffers.
                let mut unread_data_at = self.recv.nxt.wrapping_sub(seqn) as usize;
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
                self.recv.nxt = seqn.wrapping_add(data.len() as u32);

                // Send an acknowledgment of the form:
                //   <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                //
                // TODO: maybe just tick to piggyback ack on data
                // This acknowledgment should be piggybacked on a segment being
                // transmitted if possible without incurring undue delay.
                self.write(nic, self.send.nxt, 0)?;
            }
        }

        // RFC 793 Page 75, eighth check the FIN bit
        //
        // If the FIN bit is set, signal the user "connection closing" and
        // return any pending RECEIVEs with same message, advance RCV.NXT
        // over the FIN, and send an acknowledgment for the FIN.  Note that
        // FIN implies PUSH for any segment text not yet delivered to the
        // user.
        if tcph.fin() {
            // TODO: 测试的时候注意看一下这里，是否有其他的 state 进入
            eprintln!("IS FIN (in {:?}) --", self.state);
            match self.state {
                State::FinWait2 => {
                    // we're done with the connection!
                    self.recv.nxt = self.recv.nxt.wrapping_add(1);
                    self.write(nic, self.send.nxt, 0)?;
                    self.state = State::TimeWait;
                }
                _ => unimplemented!(),
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
