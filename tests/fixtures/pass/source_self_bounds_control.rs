trait HasAssoc {
    type Assoc;
    const SIZE: usize;
}
trait Uses<T> {}
trait RefMarker {}

impl<T> RefMarker for &T {}

struct Plain<'a, T, const N: usize>
where
    Self: Uses<Self>,
    <Self as HasAssoc>::Assoc: Clone,
    for<'b> &'b Self: RefMarker,
{
    value: &'a T,
    bytes: [u8; N],
}

impl<'a, T, const N: usize> HasAssoc for Plain<'a, T, N> {
    type Assoc = u8;
    const SIZE: usize = N;
}
impl<'a, T, const N: usize> Uses<Plain<'a, T, N>> for Plain<'a, T, N> {}

fn main() {
    let text = "valid";
    let value = Plain::<_, 2> {
        value: &text,
        bytes: [1, 2],
    };
    assert_eq!(value.value, &"valid");
}
