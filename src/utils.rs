use std::marker::PhantomData;

use futures::{Async, Stream};

#[macro_export]
macro_rules! default_addr {
    () => { ::std::net::SocketAddrV6::new(::std::net::Ipv6Addr::from([0u8; 16]), 0, 0, 0) };
}

pub struct IgnoreErrors<S: Stream, E> {
    inner: S,
    err_phantom: PhantomData<E>,
}

impl<S: Stream, E> Stream for IgnoreErrors<S, E> {
    type Item = S::Item;
    type Error = E;

    fn poll(&mut self) -> Result<Async<Option<S::Item>>, E> {
        loop {
            if let Ok(x) = self.inner.poll() {
                return Ok(x);
            }
        }
    }
}

pub fn ignore_errors<E, S: Stream>(stream: S) -> IgnoreErrors<S, E> {
    IgnoreErrors {
        inner: stream,
        err_phantom: PhantomData,
    }
}
