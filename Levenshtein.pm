package Mail::SpamAssassin::Plugin::Levenshtein;
my $VERSION = 0.01;

use strict;
use Mail::SpamAssassin::Plugin;
use File::Basename;
use List::Util ();


use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

sub dbg { Mail::SpamAssassin::Plugin::dbg ("Levenshtein: @_"); }

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  # the important bit!
  $self->register_eval_rule("check_levenshtein_from");

  return $self;
}

sub check_levenshtein_from
{
  my ($self, $pms, $str, $tdist, $ignore_tld) = @_;

  my $re = '^((?![0-9]+$)(?!.*-$)(?!-)[a-zA-Z0-9-]{1,63})';

  if (!$ignore_tld) {
    $str =~ /$re/;
    $str = $1;
  }

  foreach ($pms->all_from_addrs_domains()) {
      $_ = Mail::SpamAssassin::Util::uri_to_domain($_) || $_;

      if (!$ignore_tld) {
        $_ =~ /$re/;
        $_ =  $1;
      }

      my $distance = distance($str, $_);
      dbg("Distance from $str to $_ = $distance");

      if (($distance > 0) && ($distance <= $tdist)) {
        return 1;
      }
  }
  return 0;
}

# Taken from CPAN module at
#
# http://search.cpan.org/dist/Text-Levenshtein/lib/Text/Levenshtein.pm
#
# This software is copyright (C) 2002-2004 Dree Mistrut.
# Copyright (C) 2004-2014 Josh Goldberg.
# Copyright (C) 2014- Neil Bowers.
#

sub distance
{
    my $opt = pop(@_) if @_ > 0 && ref($_[-1]) eq 'HASH';
    die "distance() takes 2 or more arguments" if @_ < 2;
	my ($s,@t)=@_;
    my @results;

    $opt = {} if not defined $opt;

	foreach my $t (@t) {
		push(@results, fastdistance($s, $t, $opt));
	}

	return wantarray ? @results : $results[0];
}

my $eq_with_diacritics = sub {
    my ($x, $y) = @_;
    return $x eq $y;
};

my $eq_without_diacritics;

# This is the "Iterative with two matrix rows" version
# from the wikipedia page
# http://en.wikipedia.org/wiki/Levenshtein_distance#Computing_Levenshtein_distance
sub fastdistance
{
    my $opt = pop(@_) if @_ > 0 && ref($_[-1]) eq 'HASH';
    die "fastdistance() takes 2 or 3 arguments" unless @_ == 2;
    my ($s, $t) = @_;
    my (@v0, @v1);
    my ($i, $j);
    my $eq;

    $opt = {} if not defined $opt;
    if ($opt->{ignore_diacritics}) {
        if (not defined $eq_without_diacritics) {
            require Unicode::Collate;
            my $collator = Unicode::Collate->new(normalization => undef, level => 1);
            $eq_without_diacritics = sub {
                return $collator->eq(@_);
            };
        }
        $eq = $eq_without_diacritics;
    }
    else {
        $eq = $eq_with_diacritics;
    }

    return 0 if $s eq $t;
    return length($s) if !$t || length($t) == 0;
    return length($t) if !$s || length($s) == 0;

    my $s_length = length($s);
    my $t_length = length($t);

    for ($i = 0; $i < $t_length + 1; $i++) {
        $v0[$i] = $i;
    }

    for ($i = 0; $i < $s_length; $i++) {
        $v1[0] = $i + 1;

        for ($j = 0; $j < $t_length; $j++) {
            # my $cost = substr($s, $i, 1) eq substr($t, $j, 1) ? 0 : 1;
            my $cost = $eq->(substr($s, $i, 1), substr($t, $j, 1)) ? 0 : 1;
            $v1[$j + 1] = List::Util::min(
                              $v1[$j] + 1,
                              $v0[$j + 1] + 1,
                              $v0[$j] + $cost,
                             );
        }

        for ($j = 0; $j < $t_length + 1; $j++) {
            $v0[$j] = $v1[$j];
        }
    }

    return $v1[ $t_length];
}

1;
