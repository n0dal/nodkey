# SPDX-FileCopyrightText: 2026 Henry Cuevas
# SPDX-License-Identifier: Apache-2.0
#
# Demo P socket-P test client (attacker J: code running as the BROKER uid inside the broker
# container, or as another uid for the wrong-peer case). perl-base only (no JSON module): stdin is
# one line "concurrent=0|1" followed by one request line per P call; each response line (or an
# error marker) is printed on its own line, in request order.
use strict; use warnings;
use IO::Socket::UNIX; use Socket;
my $sock = $ENV{P_SOCK} // '/run/nodkey/br-pay/adapter.sock';
my $first = <STDIN>; my $conc = ($first // '') =~ /concurrent=1/ ? 1 : 0;
my @lines = grep { length } map { chomp; $_ } <STDIN>;
sub one {
  my ($l) = @_;
  my $s = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $sock) or return "\"connect_failed: $!\"";
  print $s $l, "\n"; shutdown($s, 1);
  local $SIG{ALRM} = sub { die "timeout\n" }; alarm 30;
  my $r = eval { <$s> }; alarm 0;
  return defined $r ? do { chomp $r; $r } : '"no_response"';
}
if (!$conc) { print one($_), "\n" for @lines; exit 0; }
# Concurrent: one child per request, each answering through its own pipe (rootfs is read-only).
my @kids;
for my $l (@lines) {
  pipe(my $r, my $w) or die "pipe";
  my $pid = fork(); die "fork" unless defined $pid;
  if ($pid == 0) { close $r; print $w one($l), "\n"; close $w; exit 0; }
  close $w; push @kids, [$pid, $r];
}
for my $k (@kids) { my $fh = $k->[1]; my $out = <$fh>; print $out // "\"no_output\"\n"; close $fh; waitpid($k->[0], 0); }
