use wasm_bindgen::prelude::*;

use anyhow::Error;
use lancelot::{
    analysis::dis::zydis,
    arch::Arch,
    aspace::AddressSpace,
    loader::pe::{PEError, PE as lPE},
    module::{ModuleError, Permissions},
    pagemap::PageMapError,
    util::UtilError,
    VA,
};

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub fn version() -> String {
    String::from("v0.7.0")
}

#[wasm_bindgen(start)]
pub fn main_js() -> Result<(), JsValue> {
    #[cfg(debug_assertions)]
    console_error_panic_hook::set_once();

    Ok(())
}

fn to_value_error(e: anyhow::Error) -> JsValue {
    js_sys::Error::new(&format!("{}", e)).into()
}

fn to_js_err(e: Error) -> JsValue {
    match e.downcast_ref::<PEError>() {
        Some(PEError::FormatNotSupported(_)) => return to_value_error(e),
        Some(PEError::MalformedPEFile(_)) => return to_value_error(e),
        None => (),
    };

    #[allow(clippy::single_match)]
    match e.downcast_ref::<ModuleError>() {
        Some(ModuleError::InvalidAddress(_)) => return to_value_error(e),
        None => (),
    };

    match e.downcast_ref::<UtilError>() {
        Some(UtilError::FileAccess) => return to_value_error(e),
        Some(UtilError::FileFormat) => return to_value_error(e),
        None => (),
    };

    #[allow(clippy::single_match)]
    match e.downcast_ref::<PageMapError>() {
        Some(PageMapError::NotMapped) => return to_value_error(e),
        None => (),
    };

    to_value_error(e)
}

#[wasm_bindgen]
pub fn from_bytes(buf: Vec<u8>) -> Result<PE, JsValue> {
    use lancelot::analysis::dis;
    let pe = lPE::from_bytes(&buf).map_err(to_js_err)?;
    let dec = dis::get_disassembler(&pe.module).map_err(to_js_err)?;
    Ok(PE {
        inner:   pe,
        decoder: dec,
    })
}

#[wasm_bindgen]
pub struct PE {
    inner:   lPE,
    decoder: zydis::Decoder,
}

#[wasm_bindgen]
impl PE {
    #[wasm_bindgen(getter)]
    pub fn arch(&self) -> String {
        match self.inner.module.arch {
            Arch::X32 => String::from("x32"),
            Arch::X64 => String::from("x64"),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn base_address(&self) -> u64 {
        self.inner.module.address_space.base_address
    }

    #[wasm_bindgen(getter)]
    pub fn functions(&self) -> Result<Vec<u64>, JsValue> {
        Ok(lancelot::analysis::pe::find_functions(&self.inner)
            .map_err(to_js_err)?
            .into_iter()
            .filter(|f| matches!(f, lancelot::analysis::pe::Function::Local(_)))
            .map(|f| match f {
                lancelot::analysis::pe::Function::Local(va) => va,
                _ => unreachable!(),
            })
            .collect())
    }
}
