use radius2::{Radius, RadiusOption};

fn main() {
    let options = [
        RadiusOption::Debug(true),
        //RadiusOption::Sims(false),
        RadiusOption::LoadPlugins(true),
    ];
    
    let mut radius = Radius::new_with_options(Some("frida://attach/usb//com.nowsecure.escrackme"), &options);

    radius.cmd("s `:il~ base.odex`");

    let addr_str = radius.cmd(":is~com.nowsecure.escrackme.MainActivity.check").unwrap()
    .split(" ")
    .next()
    .unwrap_or("").to_string();

    let addr_int = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16).unwrap();

    let mut state = radius.call_state(addr_int);
    let bv = state.symbolic_value("flag", 64);

    state.registers.set("x2", bv.clone());
    
    
    let mut new_state = radius.run_until(state, addr_int + (7*16), &[addr_int + (2 * 16)]).unwrap();


    let w0 = new_state.registers.get("w0");
    new_state.assert(&w0);
    let flag = new_state.eval(&bv).unwrap().as_u64().unwrap();
    
    println!("FLAG: {:x}", flag);
}