// Licensed under the Apache-2.0 license.
//
// generated by caliptra_registers_generator with caliptra-rtl repo at 5ca1be7022f252bb369ae61f6db28b8556c03f03
//
#![allow(clippy::erasing_op)]
#![allow(clippy::identity_op)]
/// A zero-sized type that represents ownership of this
/// peripheral, used to get access to a Register lock. Most
/// programs create one of these in unsafe code near the top of
/// main(), and pass it to the driver responsible for managing
/// all access to the hardware.
pub struct El2PicCtrl {
    _priv: (),
}
impl El2PicCtrl {
    pub const PTR: *mut u32 = 0x60000000 as *mut u32;
    /// # Safety
    ///
    /// Caller must ensure that all concurrent use of this
    /// peripheral in the firmware is done so in a compatible
    /// way. The simplest way to enforce this is to only call
    /// this function once.
    #[inline(always)]
    pub unsafe fn new() -> Self {
        Self { _priv: () }
    }
    /// Returns a register block that can be used to read
    /// registers from this peripheral, but cannot write.
    #[inline(always)]
    pub fn regs(&self) -> RegisterBlock<ureg::RealMmio> {
        RegisterBlock {
            ptr: Self::PTR,
            mmio: core::default::Default::default(),
        }
    }
    /// Return a register block that can be used to read and
    /// write this peripheral's registers.
    #[inline(always)]
    pub fn regs_mut(&mut self) -> RegisterBlock<ureg::RealMmioMut> {
        RegisterBlock {
            ptr: Self::PTR,
            mmio: core::default::Default::default(),
        }
    }
}
#[derive(Clone, Copy)]
pub struct RegisterBlock<TMmio: ureg::Mmio + core::borrow::Borrow<TMmio>> {
    ptr: *mut u32,
    mmio: TMmio,
}
impl<TMmio: ureg::Mmio + core::default::Default> RegisterBlock<TMmio> {
    /// # Safety
    ///
    /// The caller is responsible for ensuring that ptr is valid for
    /// volatile reads and writes at any of the offsets in this register
    /// block.
    #[inline(always)]
    pub unsafe fn new(ptr: *mut u32) -> Self {
        Self {
            ptr,
            mmio: core::default::Default::default(),
        }
    }
}
impl<TMmio: ureg::Mmio> RegisterBlock<TMmio> {
    /// # Safety
    ///
    /// The caller is responsible for ensuring that ptr is valid for
    /// volatile reads and writes at any of the offsets in this register
    /// block.
    #[inline(always)]
    pub unsafe fn new_with_mmio(ptr: *mut u32, mmio: TMmio) -> Self {
        Self { ptr, mmio }
    }
    /// There are 255 priority level registers, one for each external
    /// interrupt source. Implementing individual priority level
    /// registers allows a debugger to autonomously discover how many
    /// priority level bits are supported for this interrupt source.
    /// Firmware must initialize the priority level for each used
    /// interrupt source. Firmware may also read the priority level.
    ///
    /// Read value: [`el2_pic_ctrl::regs::MeiplReadVal`]; Write value: [`el2_pic_ctrl::regs::MeiplWriteVal`]
    #[inline(always)]
    pub fn meipl(
        &self,
    ) -> ureg::Array<256, ureg::RegRef<crate::el2_pic_ctrl::meta::Meipl, &TMmio>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Eight external interrupt pending registers are needed to
    /// report the current status of up to 255 independent external
    /// interrupt sources. Each bit of these registers corresponds
    /// to an interrupt pending indication of a single external
    /// interrupt source. These registers only provide the status
    /// of pending interrupts and cannot be written.
    ///
    /// Read value: [`el2_pic_ctrl::regs::MeipReadVal`]; Write value: [`el2_pic_ctrl::regs::MeipWriteVal`]
    #[inline(always)]
    pub fn meip(&self) -> ureg::Array<256, ureg::RegRef<crate::el2_pic_ctrl::meta::Meip, &TMmio>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0x1000 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Each of the up to 255 independently controlled external
    /// interrupt sources has a dedicated interrupt enable register.
    /// Separate registers per interrupt source were chosen for
    /// ease-of-use and compatibility with existing controllers.
    ///
    /// Read value: [`el2_pic_ctrl::regs::MeieReadVal`]; Write value: [`el2_pic_ctrl::regs::MeieWriteVal`]
    #[inline(always)]
    pub fn meie(&self) -> ureg::Array<256, ureg::RegRef<crate::el2_pic_ctrl::meta::Meie, &TMmio>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0x2000 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// The PIC configuration register is used to select the operational
    /// parameters of the PIC.
    ///
    /// Read value: [`el2_pic_ctrl::regs::MpiccfgReadVal`]; Write value: [`el2_pic_ctrl::regs::MpiccfgWriteVal`]
    #[inline(always)]
    pub fn mpiccfg(&self) -> ureg::RegRef<crate::el2_pic_ctrl::meta::Mpiccfg, &TMmio> {
        unsafe {
            ureg::RegRef::new_with_mmio(
                self.ptr.wrapping_add(0x3000 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Each configurable gateway has a dedicated configuration register
    /// to control the interrupt type (i.e., edge- vs. level-triggered)
    /// as well as the interrupt signal polarity (i.e., low-to-high vs.
    /// high-to-low transition for edge-triggered interrupts, active-high
    /// vs. -low for level-triggered interrupts).
    ///
    /// Read value: [`el2_pic_ctrl::regs::MeigwctrlReadVal`]; Write value: [`el2_pic_ctrl::regs::MeigwctrlWriteVal`]
    #[inline(always)]
    pub fn meigwctrl(
        &self,
    ) -> ureg::Array<256, ureg::RegRef<crate::el2_pic_ctrl::meta::Meigwctrl, &TMmio>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0x4000 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
    /// Each configurable gateway has a dedicated clear register
    /// to reset its interrupt pending (IP) bit. For edge-triggered
    /// interrupts, firmware must clear the gateway’s IP bit while
    /// servicing the external interrupt of source ID S by writing to
    /// the meigwclrS register.
    ///
    /// Read value: [`u32`]; Write value: [`u32`]
    #[inline(always)]
    pub fn meigwclr(
        &self,
    ) -> ureg::Array<256, ureg::RegRef<crate::el2_pic_ctrl::meta::Meigwclr, &TMmio>> {
        unsafe {
            ureg::Array::new_with_mmio(
                self.ptr.wrapping_add(0x5000 / core::mem::size_of::<u32>()),
                core::borrow::Borrow::borrow(&self.mmio),
            )
        }
    }
}
pub mod regs {
    //! Types that represent the values held by registers.
    #[derive(Clone, Copy)]
    pub struct MeieReadVal(u32);
    impl MeieReadVal {
        /// External interrupt enable
        #[inline(always)]
        pub fn inten(&self) -> bool {
            ((self.0 >> 0) & 1) != 0
        }
        /// Construct a WriteVal that can be used to modify the contents of this register value.
        #[inline(always)]
        pub fn modify(self) -> MeieWriteVal {
            MeieWriteVal(self.0)
        }
    }
    impl From<u32> for MeieReadVal {
        #[inline(always)]
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<MeieReadVal> for u32 {
        #[inline(always)]
        fn from(val: MeieReadVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct MeieWriteVal(u32);
    impl MeieWriteVal {
        /// External interrupt enable
        #[inline(always)]
        pub fn inten(self, val: bool) -> Self {
            Self((self.0 & !(1 << 0)) | (u32::from(val) << 0))
        }
    }
    impl From<u32> for MeieWriteVal {
        #[inline(always)]
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<MeieWriteVal> for u32 {
        #[inline(always)]
        fn from(val: MeieWriteVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct MeigwctrlReadVal(u32);
    impl MeigwctrlReadVal {
        /// External interrupt polarity
        /// 0b0: Active-high interrupt
        /// 0b1: Active-low interrupt
        #[inline(always)]
        pub fn polarity(&self) -> bool {
            ((self.0 >> 0) & 1) != 0
        }
        /// External interrupt type
        /// 0b0: Level-triggered interrupt
        /// 0b1: Edge-triggered interrupt
        #[inline(always)]
        pub fn inttype(&self) -> bool {
            ((self.0 >> 1) & 1) != 0
        }
        /// Construct a WriteVal that can be used to modify the contents of this register value.
        #[inline(always)]
        pub fn modify(self) -> MeigwctrlWriteVal {
            MeigwctrlWriteVal(self.0)
        }
    }
    impl From<u32> for MeigwctrlReadVal {
        #[inline(always)]
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<MeigwctrlReadVal> for u32 {
        #[inline(always)]
        fn from(val: MeigwctrlReadVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct MeigwctrlWriteVal(u32);
    impl MeigwctrlWriteVal {
        /// External interrupt polarity
        /// 0b0: Active-high interrupt
        /// 0b1: Active-low interrupt
        #[inline(always)]
        pub fn polarity(self, val: bool) -> Self {
            Self((self.0 & !(1 << 0)) | (u32::from(val) << 0))
        }
        /// External interrupt type
        /// 0b0: Level-triggered interrupt
        /// 0b1: Edge-triggered interrupt
        #[inline(always)]
        pub fn inttype(self, val: bool) -> Self {
            Self((self.0 & !(1 << 1)) | (u32::from(val) << 1))
        }
    }
    impl From<u32> for MeigwctrlWriteVal {
        #[inline(always)]
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<MeigwctrlWriteVal> for u32 {
        #[inline(always)]
        fn from(val: MeigwctrlWriteVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct MeipReadVal(u32);
    impl MeipReadVal {
        /// External interrupt pending
        #[inline(always)]
        pub fn intpend(&self) -> bool {
            ((self.0 >> 0) & 1) != 0
        }
    }
    impl From<u32> for MeipReadVal {
        #[inline(always)]
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<MeipReadVal> for u32 {
        #[inline(always)]
        fn from(val: MeipReadVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct MeiplReadVal(u32);
    impl MeiplReadVal {
        /// External interrupt priority level
        #[inline(always)]
        pub fn priority(&self) -> u32 {
            (self.0 >> 0) & 0xf
        }
        /// Construct a WriteVal that can be used to modify the contents of this register value.
        #[inline(always)]
        pub fn modify(self) -> MeiplWriteVal {
            MeiplWriteVal(self.0)
        }
    }
    impl From<u32> for MeiplReadVal {
        #[inline(always)]
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<MeiplReadVal> for u32 {
        #[inline(always)]
        fn from(val: MeiplReadVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct MeiplWriteVal(u32);
    impl MeiplWriteVal {
        /// External interrupt priority level
        #[inline(always)]
        pub fn priority(self, val: u32) -> Self {
            Self((self.0 & !(0xf << 0)) | ((val & 0xf) << 0))
        }
    }
    impl From<u32> for MeiplWriteVal {
        #[inline(always)]
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<MeiplWriteVal> for u32 {
        #[inline(always)]
        fn from(val: MeiplWriteVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct MpiccfgReadVal(u32);
    impl MpiccfgReadVal {
        /// Interrupt priority order
        /// 0b0: RISC-V standard compliant priority order (0=lowest to 15=highest)
        /// 0b1: Reverse priority order (15=lowest to 0=highest)
        #[inline(always)]
        pub fn priord(&self) -> bool {
            ((self.0 >> 0) & 1) != 0
        }
        /// Construct a WriteVal that can be used to modify the contents of this register value.
        #[inline(always)]
        pub fn modify(self) -> MpiccfgWriteVal {
            MpiccfgWriteVal(self.0)
        }
    }
    impl From<u32> for MpiccfgReadVal {
        #[inline(always)]
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<MpiccfgReadVal> for u32 {
        #[inline(always)]
        fn from(val: MpiccfgReadVal) -> u32 {
            val.0
        }
    }
    #[derive(Clone, Copy)]
    pub struct MpiccfgWriteVal(u32);
    impl MpiccfgWriteVal {
        /// Interrupt priority order
        /// 0b0: RISC-V standard compliant priority order (0=lowest to 15=highest)
        /// 0b1: Reverse priority order (15=lowest to 0=highest)
        #[inline(always)]
        pub fn priord(self, val: bool) -> Self {
            Self((self.0 & !(1 << 0)) | (u32::from(val) << 0))
        }
    }
    impl From<u32> for MpiccfgWriteVal {
        #[inline(always)]
        fn from(val: u32) -> Self {
            Self(val)
        }
    }
    impl From<MpiccfgWriteVal> for u32 {
        #[inline(always)]
        fn from(val: MpiccfgWriteVal) -> u32 {
            val.0
        }
    }
}
pub mod enums {
    //! Enumerations used by some register fields.
    pub mod selector {}
}
pub mod meta {
    //! Additional metadata needed by ureg.
    pub type Meipl = ureg::ReadWriteReg32<
        0,
        crate::el2_pic_ctrl::regs::MeiplReadVal,
        crate::el2_pic_ctrl::regs::MeiplWriteVal,
    >;
    pub type Meip = ureg::ReadOnlyReg32<crate::el2_pic_ctrl::regs::MeipReadVal>;
    pub type Meie = ureg::ReadWriteReg32<
        0,
        crate::el2_pic_ctrl::regs::MeieReadVal,
        crate::el2_pic_ctrl::regs::MeieWriteVal,
    >;
    pub type Mpiccfg = ureg::ReadWriteReg32<
        0,
        crate::el2_pic_ctrl::regs::MpiccfgReadVal,
        crate::el2_pic_ctrl::regs::MpiccfgWriteVal,
    >;
    pub type Meigwctrl = ureg::ReadWriteReg32<
        0,
        crate::el2_pic_ctrl::regs::MeigwctrlReadVal,
        crate::el2_pic_ctrl::regs::MeigwctrlWriteVal,
    >;
    pub type Meigwclr = ureg::ReadWriteReg32<0, u32, u32>;
}
