#[derive(Debug, Eq, PartialEq, Hash, Copy, Clone, FromPrimitive, ToPrimitive)]
#[repr(u32)]
pub enum Title {
    Iw5 = 18409,
    T5 = 18301,
    T6Xenon = 18395,
    T6Ps3 = 18396,
    T6Pc = 18397,
    T6WiiU = 18480,
    SuperNovaiOS = 5591,
    SuperNovaPS3 = 5592,
    SuperNovaWiiU = 5594,
}
