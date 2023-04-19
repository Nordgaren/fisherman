use crate::scanner::signature::FuncAddr;

pub struct InlineHook {
    pub module: String,
    pub function_address: Box<dyn FuncAddr>,
    pub hook_address: usize,
    pub return_address: usize,
}

impl InlineHook {

}
