use std::collections::HashSet;

use anyhow::Result;

use crate::{loader::pe::PE, VA};

pub mod call_targets;
pub mod control_flow_guard;
pub mod entrypoints;
pub mod exports;
pub mod patterns;
pub mod pointers;
pub mod safeseh;

pub fn find_function_starts(pe: &PE) -> Result<Vec<VA>> {
    let mut function_starts: HashSet<VA> = Default::default();

    function_starts.extend(crate::analysis::pe::entrypoints::find_pe_entrypoint(&pe)?);
    function_starts.extend(crate::analysis::pe::exports::find_pe_exports(&pe)?);
    function_starts.extend(crate::analysis::pe::safeseh::find_pe_safeseh_handlers(&pe)?);
    function_starts.extend(crate::analysis::pe::control_flow_guard::find_pe_cfguard_functions(&pe)?);
    function_starts.extend(crate::analysis::pe::call_targets::find_pe_call_targets(&pe)?);
    function_starts.extend(crate::analysis::pe::patterns::find_function_prologues(&pe)?);
    function_starts.extend(crate::analysis::pe::pointers::find_pe_nonrelocated_executable_pointers(
        &pe,
    )?);

    // TODO: validate that the code looks ok

    let mut function_starts: Vec<_> = function_starts.into_iter().collect();
    function_starts.sort_unstable();

    Ok(function_starts)
}
