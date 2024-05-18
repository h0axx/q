system"l sha256.q";
// use this page to test https://iancoleman.io/bip39/

// binary is 256 bit random number
binary:256?2;

// function to convert binary number to hexadecimal format
binToHex:{"x"${2 sv x} each reverse each reverse 8 cut reverse x};

// checksum is a first byte of sha256 hash of binary variable
checksum:first sha256 binToHex binary;

binary:11 cut binary;

mnemonic:(-1_binary),enlist (last[binary],2 vs `int$checksum);

show "entropy";

show binToHex raze binary;

show "24 passhphare id's";

show 2 sv \: flip mnemonic;


