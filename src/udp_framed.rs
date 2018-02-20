//! A custom UDPFramed which ignores sending errors.

#![allow(dead_code)]

use std::io;
use std::net::{SocketAddr, Ipv4Addr, SocketAddrV4};

use futures::{Async, Poll, Stream, Sink, StartSend, AsyncSink};

use tokio_core::net::{UdpSocket, UdpCodec};

/// A unified `Stream` and `Sink` interface to an underlying `UdpSocket`, using
/// the `UdpCodec` trait to encode and decode frames.
///
/// You can acquire a `UdpFramed` instance by using the `UdpSocket::framed`
/// adapter.
#[must_use = "sinks do nothing unless polled"]
pub struct UdpFramed<C> {
    socket: UdpSocket,
    codec: C,
    rd: Vec<u8>,
    wr: Vec<u8>,
    out_addr: SocketAddr,
    flushed: bool,
}

impl<C: UdpCodec> Stream for UdpFramed<C> {
    type Item = C::In;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<C::In>, io::Error> {
        let (n, addr) = try_nb!(self.socket.recv_from(&mut self.rd));
        trace!("received {} bytes, decoding", n);
        let frame = try!(self.codec.decode(&addr, &self.rd[..n]));
        trace!("frame decoded from buffer");
        Ok(Async::Ready(Some(frame)))
    }
}

impl<C: UdpCodec> Sink for UdpFramed<C> {
    type SinkItem = C::Out;
    type SinkError = io::Error;

    fn start_send(&mut self, item: C::Out) -> StartSend<C::Out, io::Error> {
        trace!("sending frame");

        if !self.flushed {
            match self.poll_complete() {
                Ok(Async::Ready(())) => {},
                _ => return Ok(AsyncSink::NotReady(item)),
            }
        }

        self.out_addr = self.codec.encode(item, &mut self.wr);
        self.flushed = false;
        trace!("frame encoded; length={}", self.wr.len());

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), io::Error> {
        if self.flushed {
            return Ok(Async::Ready(()))
        }

        trace!("flushing frame; length={}", self.wr.len());
        match self.socket.send_to(&self.wr, &self.out_addr) {
            Ok(n) => {
                trace!("Written {}", n);
            },
            Err(e) => {
                if e.kind() == ::std::io::ErrorKind::WouldBlock {
                    return Ok(Async::NotReady);
                }
                debug!("Error sending frame: {:?}", e);
            }
        }

        self.wr.clear();
        self.flushed = true;

        Ok(Async::Ready(()))
    }

    fn close(&mut self) -> Poll<(), io::Error> {
        try_ready!(self.poll_complete());
        Ok(().into())
    }
}

pub fn new<C: UdpCodec>(socket: UdpSocket, codec: C) -> UdpFramed<C> {
    UdpFramed {
        socket: socket,
        codec: codec,
        out_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
        rd: vec![0; 64 * 1024],
        wr: Vec::with_capacity(8 * 1024),
        flushed: true,
    }
}

impl<C> UdpFramed<C> {
    /// Returns a reference to the underlying I/O stream wrapped by `Framed`.
    ///
    /// Note that care should be taken to not tamper with the underlying stream
    /// of data coming in as it may corrupt the stream of frames otherwise being
    /// worked with.
    pub fn get_ref(&self) -> &UdpSocket {
        &self.socket
    }

    /// Returns a mutable reference to the underlying I/O stream wrapped by
    /// `Framed`.
    ///
    /// Note that care should be taken to not tamper with the underlying stream
    /// of data coming in as it may corrupt the stream of frames otherwise being
    /// worked with.
    pub fn get_mut(&mut self) -> &mut UdpSocket {
        &mut self.socket
    }

    /// Consumes the `Framed`, returning its underlying I/O stream.
    ///
    /// Note that care should be taken to not tamper with the underlying stream
    /// of data coming in as it may corrupt the stream of frames otherwise being
    /// worked with.
    pub fn into_inner(self) -> UdpSocket {
        self.socket
    }
}
