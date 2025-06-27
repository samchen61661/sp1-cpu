use hashbrown::HashMap;
use std::{
    any::Any,
    hash::Hash,
    io::{self, Read, Write},
};

pub trait SerializeProof: Sized + Any {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize>;
    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self>;
}

// (A,B) serializes A, then B.
// Other tuples serialize similarly.
// The unit () does nothing, serializes into 0 bytes and consumes 0 bytes deserializing.
// u8 serializes as itself.
// [T;N] serializes T N times.
// u32 serializes as [u8; 4], little-endian.
// Vec<T> serializes as a u32 for the lenght (in elements), and
// then each element serializes in succession.
// u64 serializes as [u8; 8], little-endian.
// usize serializes as u64.
// HashMap<K,V> serializes as Vec<(K,V)>, sorted by K.
// String serializes as Vec<u8>, deserialization fails if not UTF-8.
// bool serializes as u8. true -> 1, false -> 0

impl SerializeProof for () {
    fn to_bytes<W: Write>(self, _w: &mut W) -> io::Result<usize> {
        Ok(0)
    }

    fn from_bytes<R: Read>(_buffer: &mut R) -> io::Result<Self> {
        Ok(())
    }
}

impl<A, B, C, D, E> SerializeProof for (A, B, C, D, E)
where
    A: SerializeProof,
    B: SerializeProof,
    C: SerializeProof,
    D: SerializeProof,
    E: SerializeProof,
{
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let (a, b, c, d, e) = self;
        let mut written = a.to_bytes(w)?;
        written += b.to_bytes(w)?;
        written += c.to_bytes(w)?;
        written += d.to_bytes(w)?;
        written += e.to_bytes(w)?;
        Ok(written)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let a = A::from_bytes(buffer)?;
        let b = B::from_bytes(buffer)?;
        let c = C::from_bytes(buffer)?;
        let d = D::from_bytes(buffer)?;
        let e = E::from_bytes(buffer)?;
        Ok((a, b, c, d, e))
    }
}

impl<A: SerializeProof, B: SerializeProof> SerializeProof for (A, B) {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let (a, b) = self;
        (a, b, (), (), ()).to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let (a, b, _, _, _) = <(A, B, (), (), ())>::from_bytes(buffer)?;
        Ok((a, b))
    }
}

impl SerializeProof for u8 {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        w.write(&[self])
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let mut bytes = [0u8];
        buffer.read_exact(&mut bytes)?;
        let [byte] = bytes;
        Ok(byte)
    }
}

impl<T: SerializeProof, const N: usize> SerializeProof for [T; N] {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let mut written = 0;
        for elem in self.into_iter() {
            written += elem.to_bytes(w)?;
        }
        Ok(written)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let mut res: [Option<T>; N] = [(); N].map(|_| None);
        for i in 0..N {
            res[i] = Some(T::from_bytes(buffer)?);
        }
        Ok(res.map(Option::unwrap))
    }
}

impl SerializeProof for u32 {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let bytes: [u8; 4] = self.to_le_bytes();
        bytes.to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let mut bytes = [0_u8; 4];
        buffer.read_exact(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
}

impl<T: SerializeProof> SerializeProof for Vec<T> {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let len: u32 = self.len().try_into().unwrap();
        let mut written = 0;
        written += len.to_bytes(w)?;
        for elem in self.into_iter() {
            written += elem.to_bytes(w)?;
        }
        Ok(written)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let len = u32::from_bytes(buffer)?;
        let len = len as usize;
        let mut vec = Vec::with_capacity(len);
        for _ in 0..len {
            let val = T::from_bytes(buffer)?;
            vec.push(val);
        }
        Ok(vec)
    }
}

impl SerializeProof for u64 {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let bytes: [u8; 8] = self.to_le_bytes();
        bytes.to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let bytes = <[u8; 8]>::from_bytes(buffer)?;
        Ok(u64::from_le_bytes(bytes))
    }
}

impl SerializeProof for usize {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        (self as u64).to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let as_u64: u64 = SerializeProof::from_bytes(buffer)?;
        Ok(as_u64 as usize)
    }
}

impl<K, V> SerializeProof for HashMap<K, V>
where
    K: SerializeProof + Eq + Hash + Ord + Clone,
    V: SerializeProof,
{
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let mut as_vec: Vec<(K, V)> = self.into_iter().collect();
        as_vec.sort_by_key(|(k, _)| k.clone());
        as_vec.to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let as_vec: Vec<(K, V)> = SerializeProof::from_bytes(buffer)?;
        let mut map = HashMap::new();
        for (k, v) in as_vec {
            let present = map.insert(k, v);
            if present.is_some() {
                panic!("duplicated keys");
            }
        }
        Ok(map)
    }
}

impl SerializeProof for String {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let as_bytes: Vec<u8> = self.as_bytes().to_vec();
        as_bytes.to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let bytes: Vec<u8> = SerializeProof::from_bytes(buffer)?;
        let string = String::from_utf8(bytes).unwrap();
        Ok(string)
    }
}

impl SerializeProof for bool {
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let as_u8: u8 = if self { 1 } else { 0 };
        as_u8.to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        u8::from_bytes(buffer).map(|byte| match byte {
            0 => false,
            1 => true,
            // should be an error but for now errors are assumed to not happen.
            _ => {
                panic!("unexpected bool value")
            }
        })
    }
}

impl<A, B, C, D> SerializeProof for (A, B, C, D)
where
    A: SerializeProof,
    B: SerializeProof,
    C: SerializeProof,
    D: SerializeProof,
{
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let (a, b, c, d) = self;
        (a, b, c, d, ()).to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let (a, b, c, d, ()) = SerializeProof::from_bytes(buffer)?;
        Ok((a, b, c, d))
    }
}

impl<A, B, C> SerializeProof for (A, B, C)
where
    A: SerializeProof,
    B: SerializeProof,
    C: SerializeProof,
{
    fn to_bytes<W: Write>(self, w: &mut W) -> io::Result<usize> {
        let (a, b, c) = self;
        (a, b, c, (), ()).to_bytes(w)
    }

    fn from_bytes<R: Read>(buffer: &mut R) -> io::Result<Self> {
        let (a, b, c, (), ()) = SerializeProof::from_bytes(buffer)?;
        Ok((a, b, c))
    }
}