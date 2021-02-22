package Mail::SpamAssassin::Plugin::Levenshtein;
my $VERSION = 0.32;

use strict;
use Mail::SpamAssassin::Plugin;
use List::Util ();

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

sub dbg { Mail::SpamAssassin::Plugin::dbg ("Levenshtein: @_"); }

sub uri_to_domain {
  my ($self, $domain) = @_;

  if ($Mail::SpamAssassin::VERSION <= 3.004000) {
    Mail::SpamAssassin::Util::uri_to_domain($domain);
  } else {
    $self->{main}->{registryboundaries}->uri_to_domain($domain);
  }
}

# constructor: register the eval rule
sub new
{
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->set_config($mailsaobject->{conf});

  if (eval { require Text::Levenshtein::Damerau; }) {
    $self->{damerau_available} = 1;
    dbg("Text::Levenshtein::Damerau is available");
  }

  # the important bit!
  $self->register_eval_rule("check_levenshtein");
  $self->register_eval_rule("check_levenshtein_reply");
  $self->register_eval_rule("check_levenshtein_from");
  $self->register_eval_rule("check_levenshtein_name");

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds = ();
  push(@cmds, {
    setting => 'levenshtein_short_dist',
    default => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    }
  );
  push(@cmds, {
    setting => 'levenshtein_long_dist',
    default => 2,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    }
  );
  push(@cmds, {
    setting => 'levenshtein_short_length',
    default => 10,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    }
  );
  push(@cmds, {
    setting => 'levenshtein_use_tld',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
    }
  );

  $conf->{parser}->register_commands(\@cmds);
}

sub check_levenshtein
{
  my ($self, $pms, $tdist, $use_tld) = @_;

  my $from = $pms->get("From:addr");

  if ($self->_check_levenshtein_addr_arr($pms, $from, $tdist, $use_tld, 0, $pms->all_to_addrs())) {
    return 1;
  }

  return 0;
}

sub check_levenshtein_reply
{
  my ($self, $pms, $tdist, $use_tld) = @_;

  my $compare = $pms->get("Reply-To:addr");
  my @froms = ( $pms->get('From:addr') );

  return 0 unless $compare;

  if ($self->_check_levenshtein_addr_arr($pms, $compare, $tdist, $use_tld, 0, @froms)) {
    return 1;
  }

  return 0;
}

sub check_levenshtein_name
{
  my ($self, $pms, $compare, $tdist, $exact_match) = @_;

  my @target = split /\s/, $pms->get("From:name");

  $exact_match = defined $exact_match ? $exact_match : 1;

  if ($self->_check_levenshtein_addr_arr($pms, $compare, $tdist, 0, $exact_match, @target)) {
    return 1;
  }

  return 0;  
}

sub check_levenshtein_from
{
  my ($self, $pms, $compare, $tdist, $use_tld) = @_;

  if ($self->_check_levenshtein_addr_arr($pms, $compare, $tdist, $use_tld, 0, $pms->all_from_addrs_domains())) {
    return 1;
  }

  return 0;
}

sub _check_levenshtein_addr_arr
{
  my ($self, $pms, $from, $tdist, $use_tld, $exact_match, @to_array) = @_;
  $from = $self->uri_to_domain($from) || $from;

  return 0 if (!length $from);

  my ($fromdom, $fromtld) = _split_dom($from);
  my $flength = length $fromdom;

  return 0 if ($flength == 0);

  $tdist = defined $tdist ? $tdist : _auto_dist($pms, $fromdom);
  $use_tld = defined $use_tld ? $use_tld : $pms->{main}->{conf}->{levenshtein_use_tld};

  foreach (@to_array) {
    $_ = $self->uri_to_domain($_) || $_;
    my ($todom, $totld) = _split_dom($_);
    my $tolength = length $todom;

    next if ($tolength == 0);

    my $tld_adj = 0;
    $tld_adj = 1 if (($use_tld) && ($fromtld ne $totld));

    my $ldiff = abs($flength - $tolength) + $tld_adj;

    dbg("T1=$_ T2=$from TLD=$use_tld T=$tdist L=$ldiff");
    next if ($ldiff > $tdist);

    my $distance = $self->distance($fromdom, $todom) + $tld_adj;
    dbg("T1=$_ T2=$from TLD=$use_tld T=$tdist L=$ldiff D=$distance");

    if ((($distance > 0) || ($distance == 0 && $exact_match)) && ($distance <= $tdist)) {
      return 1;
    }

  }

  return 0;
}

sub distance
{
  my ($self, $from, $to) = @_;
  if ($self->{damerau_available}) {
    my $tld = Text::Levenshtein::Damerau->new($from);
    return $tld->dld($to);
  } else {
    return internal_distance($from, $to);
  }
}

sub _split_dom
{
  my ($input) = @_;
  my $re = '^([a-zA-Z0-9-]{1,63})(.*)$';
  $input =~ /$re/;
  my $domain = lc($1) || '';
  my $tld = lc($2) || '';
  $tld =~ s/^\.//;
  return ($domain, $tld);
}

sub _auto_dist {
  my ($pms, $input) = @_;
  return (length $input < $pms->{main}->{conf}->{levenshtein_short_length}) ? $pms->{main}->{conf}->{levenshtein_short_dist}:$pms->{main}->{conf}->{levenshtein_long_dist};
}

# Taken from CPAN module at
#
# http://search.cpan.org/dist/Text-Levenshtein/lib/Text/Levenshtein.pm
#
# This software is copyright (C) 2002-2004 Dree Mistrut.
# Copyright (C) 2004-2014 Josh Goldberg.
# Copyright (C) 2014- Neil Bowers.
#

sub internal_distance
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
