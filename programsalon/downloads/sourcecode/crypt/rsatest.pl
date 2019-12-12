#!/usr/local/bin/perl
#!/usr/bin/perl

##########################################################################
# Copyright 1996, all rights reserved.
#
# This is a perl program by Tony Chan,
# from Department of Computer Science of National Chengchi University.
# Any problems or comments please send to tony@cs.nccu.edu.tw
#
##########################################################################

%alphacode = ( "A", "00", "B", "01", "C", "02", "D", "03", "E", "04", 
               "F", "05", "G", "06", "H", "07", "I", "08", "J", "09",
               "K", "10", "L", "11", "M", "12", "N", "13", "O", "14",
               "P", "15", "Q", "16", "R", "17", "S", "18", "T", "19", 
               "U", "20", "V", "21", "W", "22", "X", "23", "Y", "24",
               "Z", "25", " ", "26", ".", "27", "?", "28", "[", "29",
               "]", "30", "0", "31", "1", "32", "2", "33", "3", "34", 
               "4", "35", "5", "36", "6", "37", "7", "38", "8", "39",
               "9", "40" );

# This is the variable e used in RSA
$RSA_e = 65537;

select STDOUT; $| = 1;

open(PRIMEFILE, "primes") || die("Can't open prime numbers file!\n");

open(PLAINFILE, "plaintext") || die("Can't open plaintext file!\n");

while (<PLAINFILE>) {
    s/(.)/$alphacode{$1}/g;
    $plaintext = $_;
}
close(PLAINFILE);
print "The original text is:\n$plaintext\n";
        

#Bypass the first line of 1-digit prime numbers
<PRIMEFILE>;

while (<PRIMEFILE>) {
    for ($i = 0; $i < 3; ++$i) {
        # Retrieve the prime pairs from the file.
        for ($j = 0; $j < 2; ++$j) {
            /(\d)+/g;
            $RSA_p = $& if ($j == 0);
            $RSA_q = $& if ($j == 1);
        }
        $RSA_n = $RSA_p * $RSA_q;
        
        print "p = $RSA_p, q = $RSA_q, n = $RSA_n. ";

        ($len_k, $dummy) = findblklen($RSA_n);
        print "length k=$len_k. ";
        $len_k *= 2;
        $len_l = $len_k+1;

        $n2 = ($RSA_p - 1)*($RSA_q - 1);
        ($dummy, $RSA_d, $dummy) = ext_euclid($RSA_e, $n2);
        $RSA_d = ($RSA_d+$n2) % $n2 if ($RSA_d < 0);
        print "Inverse d=$RSA_d\n";

        undef($ciphertext);
        undef($origtext);
        while ($plaintext =~ /\d{1,$len_k}/g) {
            $C = sprintf("%0$len_l\d", mod_exp($&, $RSA_e, $RSA_n));
            $ciphertext .= $C;
            $ciphertext .= "|";
        }
        print "C:\n$ciphertext\n\n";

        while ($ciphertext =~ /\d{1,$len_l}/g) {
            $M = sprintf("%0$len_k\d", mod_exp($&, $RSA_d, $RSA_n));
            $origtext .= $M;
            $origtext .= "|";
        }
        print "O:\n$origtext\n";
        #print "PRESS ANY KEY WHEN READY...";        
        #$line = <STDIN>;
    }
    print "\n";
    $_ = "";
}

close(PRIMEFILE);

sub ext_euclid {
    local ($a, $b) = @_;
    local ($d, $x, $y, $d_, $x_, $y_);

    return ($a, 1, 0) if ($b == 0);
    ($d_, $x_, $y_) = ext_euclid($b, $a % $b);
    ($d, $x, $y) = ($d_, $y_, $x_ - int($a/$b) * $y_);

    return ($d, $x, $y);
}

sub mod_exp {
    local ($a, $b, $n) = @_;
    local ($c, $d, $i, $k, $B);

    $c = 0;
    $d = 1;

    $B = unpack("b*", pack("L*", $b));
    $k = length($B) - 1;
    #print "k = $k\n";

    for ($i = $k; $i >= 0; --$i) {
        #$c = 2 * $c;
        $c <<= 1;
        $d = ($d * $d) % $n;
        print "a = $a, c = $c, d = $d, n = $n\n" if ($a > 100000);
        $c++, $d = ($d * $a) % $n if (substr($B, $i, 1) eq "1");
    }
    return $d;
}

sub findblklen {
    local ($n) = @_;
    local ($k, $l, $i);

    for ($i = 0; ; ++$i) {
        last if ($n > 41 ** $i && $n < 41 ** ($i+1)); 
    }

    $k = $i;
    $l = $k + 1;

    return ($k, $l);
}






