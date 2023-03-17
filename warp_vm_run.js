/**
 * warp_vm_run的函数定义不要修改
 * @param {*} vm_run_func   会调用qbdi的vm.call
 * @param {*} log_file_path 日志文件的路径
 */
export default function warp_vm_run(vm_run_func, log_file_path) {
    let baselibEncryptor = Module.findBaseAddress("libEncryptor.so");
    let addr_2BD8 = baselibEncryptor.add(0x2BD8);
    let str0 = "0123456789abcdef";
    let arg0 = Memory.allocUtf8String(str0);
    let ret_len = str0.length + 0x76;

    let arg1 = Memory.alloc(ret_len);
    let arg2 = Memory.alloc(16);
    arg2.writeU64(ret_len);

    /**
     * addr_2BD8 是主动调用函数的地址
     * [arg0, str0.length, arg1, arg2] 是参数
     * log_file_path 日志文件的路径
     */
    let ret = vm_run_func(addr_2BD8, [arg0, str0.length, arg1, arg2], log_file_path)

    console.log(ret, "\r\n", hexdump(arg1, {
        length: ret_len
    }))
}