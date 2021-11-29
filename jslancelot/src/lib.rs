use wasm_bindgen::prelude::*;

use anyhow::Error;
use lancelot::{
    arch::Arch,
    aspace::AddressSpace,
    loader::pe::{PEError, PE as lPE},
    module::ModuleError,
    pagemap::PageMapError,
    util::UtilError,
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

// for better function signatures
// no functional difference.
type JsError = JsValue;

fn to_value_error(e: anyhow::Error) -> JsError {
    js_sys::Error::new(&format!("{}", e)).into()
}

fn to_js_err(e: Error) -> JsError {
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
pub fn from_bytes(buf: Vec<u8>) -> Result<PE, JsError> {
    let pe = lPE::from_bytes(&buf).map_err(to_js_err)?;
    Ok(PE { inner: pe })
}

#[wasm_bindgen]
#[derive(Clone, Copy)]
pub struct AddressRange {
    pub start: u64,
    pub end:   u64,
}

#[wasm_bindgen]
impl AddressRange {
    #[wasm_bindgen(getter)]
    pub fn size(&self) -> u64 {
        self.end - self.start
    }
}

#[wasm_bindgen]
pub struct Section {
    pub physical_range: AddressRange,
    pub virtual_range:  AddressRange,
    // String are not clone, so we have to manually implement getters
    permissions:        String,
    name:               String,
}

#[wasm_bindgen]
impl Section {
    #[wasm_bindgen(getter)]
    pub fn permissions(&self) -> String {
        self.permissions.to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.name.clone()
    }
}

impl From<&lancelot::module::Section> for Section {
    fn from(other: &lancelot::module::Section) -> Section {
        Section {
            physical_range: AddressRange {
                start: other.physical_range.start,
                end:   other.physical_range.end,
            },
            virtual_range:  AddressRange {
                start: other.virtual_range.start,
                end:   other.virtual_range.end,
            },
            permissions:    other.permissions.to_string(),
            name:           other.name.to_string(),
        }
    }
}

#[wasm_bindgen]
pub struct PE {
    inner: lPE,
}

#[wasm_bindgen]
impl PE {
    #[wasm_bindgen(getter)]
    pub fn arch(&self) -> JsValue {
        match self.inner.module.arch {
            // we expect these strings may be returned many times,
            // so we intern them for perf
            // https://docs.rs/wasm-bindgen/0.2.78/wasm_bindgen/fn.intern.html
            Arch::X32 => JsValue::from(wasm_bindgen::intern("x32")),
            Arch::X64 => JsValue::from(wasm_bindgen::intern("x64")),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn base_address(&self) -> u64 {
        self.inner.module.address_space.base_address
    }

    // not cheap, so its a function, not getter
    #[wasm_bindgen]
    pub fn functions(&self) -> Result<Vec<u64>, JsError> {
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

    // Vec<T> cannot be serialized by wasm-bindgen
    // so we have to manually convert to Vec<JsValue>
    // and then annotate the TS type.
    //
    // NB: JS now owns the objects, must explicitly drop.
    #[wasm_bindgen(getter, typescript_type = "Array<Section>")]
    pub fn sections(&self) -> Vec<JsValue> {
        self.inner
            .module
            .sections
            .iter()
            .map(Section::from)
            .map(JsValue::from)
            .collect()
    }

    #[wasm_bindgen]
    pub fn read_bytes(&self, va: u64, size: usize) -> Result<Vec<u8>, JsError> {
        self.inner.module.address_space.read_bytes(va, size).map_err(to_js_err)
    }
}
