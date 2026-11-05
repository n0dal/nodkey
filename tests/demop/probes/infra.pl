# SPDX-FileCopyrightText: 2026 n0dal
# SPDX-License-Identifier: Apache-2.0
#
# Demo P infrastructure probe (perl-base only). Runs inside a TRUSTED container (broker, adapter,
# gateway, authority) as that container's uid, i.e. as attacker J/I code would. Arguments:
#   tcp=<ip>:<port> ...   connect attempts (1.5 s timeout)
#   path=<p> ...          existence checks
#   raw                   try AF_PACKET and SOCK_RAW sockets
#   scan                  print secret-shaped tokens from env, /proc/*/environ, /proc/*/cmdline, files
# Output: one "key<TAB>value" line per check.
use strict; use warnings; use Socket; use IO::Socket::INET;
for my $a (@ARGV) {
  if ($a =~ /^tcp=(.+)$/) {
    my $s = IO::Socket::INET->new(PeerAddr => $1, Proto => 'tcp', Timeout => 1.5);
    print "tcp $1\t", ($s ? 'connected' : "blocked($!)"), "\n"; close $s if $s;
  } elsif ($a =~ /^path=(.+)$/) {
    print "path $1\t", (-e $1 ? 'present' : 'absent'), "\n";
  } elsif ($a eq 'raw') {
    my $ok1 = socket(my $p, 17, SOCK_RAW, 0);   # AF_PACKET = 17
    print "raw AF_PACKET\t", ($ok1 ? 'created' : "refused($!)"), "\n";
    my $ok2 = socket(my $r, AF_INET, SOCK_RAW, 1); # ICMP raw
    print "raw AF_INET\t", ($ok2 ? 'created' : "refused($!)"), "\n";
  } elsif ($a eq 'scan') {
    my %c; my $files = 0;
    my $scan = sub { my $t = shift // ''; $c{$1} = 1 while $t =~ /(rk_sim_[A-Za-z0-9_]+|sk_sim_[A-Za-z0-9_]+|(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f]))/g; };
    $scan->(join("\n", map { "$_=$ENV{$_}" } keys %ENV));
    for my $p (glob('/proc/[0-9]*')) { for my $f ("$p/environ", "$p/cmdline") { if (open(my $h, '<', $f)) { local $/; $scan->(<$h>); close $h; } } }
    my @stack = map { [$_, 0] } qw(/etc /run /tmp /var /home /root /usr/local/etc /opt /srv /mnt);
    while (my $e = pop @stack) {
      my ($d, $depth) = @$e; next if $depth > 8 || $files > 20000;
      opendir(my $dh, $d) or next; my @ents = grep { $_ ne '.' && $_ ne '..' } readdir $dh; closedir $dh;
      for my $n (@ents) { my $p = "$d/$n"; next if -l $p;
        if (-d $p) { push @stack, [$p, $depth + 1]; next; }
        if (-f $p && -r $p && (-s $p // 0) < 1048576) { $files++; if (open(my $h, '<', $p)) { local $/; $scan->(<$h>); close $h; } } }
    }
    print "scan files\t$files\n"; print "token\t$_\n" for sort keys %c;
  }
}
if (open(my $h, '<', '/proc/self/status')) { while (<$h>) { print "status $1\t$2\n" if /^(CapEff|NoNewPrivs|Seccomp):\s*(\S+)/; } }
if (open(my $h, '<', '/proc/net/dev')) { my @i; while (<$h>) { push @i, $1 if /^\s*([^:\s]+):/; } print "ifaces\t", join(',', @i), "\n"; }
my @listen;
for my $f ('/proc/net/tcp', '/proc/net/tcp6') { if (open(my $h, '<', $f)) { <$h>; while (<$h>) { my @x = split; push @listen, $x[1] if ($x[3] // '') eq '0A'; } } }
print "listen_tcp\t", (@listen ? join(',', @listen) : 'none'), "\n";
