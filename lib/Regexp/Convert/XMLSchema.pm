package Regexp::Transform::XMLSchema;

use 5.008;
use strict;
use warnings;
use Data::Dumper;
use YAPE::Regex;
use Set::IntSpan qw'';
use Carp qw'croak';

use base qw(Exporter);

our $VERSION = '0.01';

# Exports
our @EXPORT_OK = qw/&re_pl2schema/;

# valid single character escapes in XML Schema.
my %escapes = (("\n" => 1), ("\r" => 1), ("\t" => 1),
map { $_ => 1 } qw/
  \\ | . - ^ ? * + { } ( ) [ ]
/);

# block names supported by XML Schema 1.0
my %legalblocks = map { $_ => 1} qw(
  AlphabeticPresentationForms
  Arabic
  ArabicPresentationForms-A
  ArabicPresentationForms-B
  Armenian
  Arrows
  BasicLatin
  Bengali
  BlockElements
  Bopomofo
  BopomofoExtended
  BoxDrawing
  BraillePatterns
  Cherokee
  CJKCompatibility
  CJKCompatibilityForms
  CJKCompatibilityIdeographs
  CJKRadicalsSupplement
  CJKSymbolsandPunctuation
  CJKUnifiedIdeographs
  CJKUnifiedIdeographsExtensionA
  CombiningDiacriticalMarks
  CombiningHalfMarks
  CombiningMarksforSymbols
  ControlPictures
  CurrencySymbols
  Cyrillic
  Devanagari
  Dingbats
  EnclosedAlphanumerics
  EnclosedCJKLettersandMonths
  Ethiopic
  GeneralPunctuation
  GeometricShapes
  Georgian
  Greek
  GreekExtended
  Gujarati
  Gurmukhi
  HalfwidthandFullwidthForms
  HangulCompatibilityJamo
  HangulJamo
  HangulSyllables
  Hebrew
  Hiragana
  IdeographicDescriptionCharacters
  IPAExtensions
  Kanbun
  KangxiRadicals
  Kannada
  Katakana
  Khmer
  Lao
  Latin-1Supplement
  LatinExtended-A
  LatinExtended-B
  LatinExtendedAdditional
  LetterlikeSymbols
  Malayalam
  MathematicalOperators
  MiscellaneousSymbols
  MiscellaneousTechnical
  Mongolian
  Myanmar
  NumberForms
  Ogham
  OpticalCharacterRecognition
  Oriya
  PrivateUse
  Runic
  Sinhala
  SmallFormVariants
  SpacingModifierLetters
  Specials
  SuperscriptsandSubscripts
  Syriac
  Tamil
  Telugu
  Thaana
  Thai
  Tibetan
  UnifiedCanadianAboriginalSyllabics
  YiRadicals
  YiSyllables
);

# XML Schema 1.0 only supports the short category
# names while Perl also supports the long names
my %catlong2short = (
  Letter               => 'L',
  CasedLetter          => 'LC',
  UppercaseLetter      => 'Lu',
  LowercaseLetter      => 'Ll',
  TitlecaseLetter      => 'Lt',
  ModifierLetter       => 'Lm',
  OtherLetter          => 'Lo',
  Mark                 => 'M',
  NonspacingMark       => 'Mn',
  SpacingMark          => 'Mc',
  EnclosingMark        => 'Me',
  Number               => 'N',
  DecimalNumber        => 'Nd',
  LetterNumber         => 'Nl',
  OtherNumber          => 'No',
  Punctuation          => 'P',
  ConnectorPunctuation => 'Pc',
  DashPunctuation      => 'Pd',
  OpenPunctuation      => 'Ps',
  ClosePunctuation     => 'Pe',
  InitialPunctuation   => 'Pi',
  FinalPunctuation     => 'Pf',
  OtherPunctuation     => 'Po',
  Symbol               => 'S',
  MathSymbol           => 'Sm',
  CurrencySymbol       => 'Sc',
  ModifierSymbol       => 'Sk',
  OtherSymbol          => 'So',
  Separator            => 'Z',
  SpaceSeparator       => 'Zs',
  LineSeparator        => 'Zl',
  ParagraphSeparator   => 'Zp',
  Other                => 'C',
  Control              => 'Cc',
  Format               => 'Cf',
  PrivateUse           => 'Co',
  Unassigned           => 'Cn',
);

# YAPE::Regex handler
my %handler = (
  oct         => \&char,     # \0
  hex         => \&char,     # \x
  ctrl        => \&char,     # \c
  named       => \&char,     # \p{...}
  comment     => \&noop,     # ?#
  whitespace  => \&noop,     # .../x
  class       => \&class,    # []
  flags       => undef,      # ?-
  slash       => \&verbatim, # \t
  group       => \&group,    # (?:
  macro       => \&verbatim, # wWdDsS
  any         => \&verbatim, # .
  alt         => \&verbatim, # |
  capture     => \&verbatim, # (
  close       => \&gclose,   # )
  text        => \&escape,   # Hello

  # http://rt.cpan.org/Public/Bug/Display.html?id=17072
  utf8hex     => undef,      # \x{20ac}
  anchor      => undef,      # ^
  backref     => undef,      # \1
  Cchar       => undef,      # \C
  cut         => undef,      # ?>
  lookahead   => undef,      # ?!
  lookbehind  => undef,      # ?<=
  conditional => undef,      # ?()
  code        => undef,      # ?{}
  later       => undef,      # ?{{}}
);

#
# Characters allowed in XML 1.0 documents. If the resulting
# regular expression will only be used in XML 1.1 documents
# it should be 1-55295,57344-65533,65536-1114111 instead to
# preserve more of the original expression.
#
my $xmlin = Set::IntSpan->new("9,10,13,32-55295,57344-65533,65536-1114111");

# Characters *not* allowed in XML 1.0 documents.
my $xmlout = $xmlin->complement;

# the boundaries this module deals with typically contain special
# characters like U+10FFFF Perl would otherwise complain about. We
# can safely ignore this here.
no warnings 'utf8';

sub esc {
    return '\\r' if $_[0] == 0x0d;
    return '\\n' if $_[0] == 0x0a;
    return '\\t' if $_[0] == 0x09;
    return '\\' . chr $_[0] if $_[0] < 255 and $escapes{chr$_[0]};
    return chr $_[0];
}

sub noop {
    # ignore this chunk
    ""
}

sub char {
    my $chunk = shift;
    my $char = "";
    
    if ($chunk->type eq 'hex') {
        $chunk->text =~ /^\\(.*)/;
        $char = hex $1;
    } elsif ($chunk->type eq 'oct') {
        $chunk->text =~ /^\\(.*)/;
        $char = oct $1;
    } elsif ($chunk->type eq 'named') {
        require charnames;
        # TODO: test this
        $char = chr charname::vianame($chunk->text);
    } elsif ($chunk->type eq 'ctrl') {
        $char = $chunk->text;
        $char = ord(eval qq(qq($char)));
    } else {
        # this should not happen
    }
    
    return esc($char);
}

sub class {
    my $chunk = shift;
    my $neg = $chunk->{NEG};
    my($text) = $chunk->text =~ /^\[\^?(.*)\]$/s;
    
    # TODO: support for [:alpha:] and such, or at least
    # croak when we encounter them.
    
    # TODO: support \p and \P when outside character class
    # see below for inside character class...
    
    # \p would trigger this
    croak "Unsupported character class" unless defined $text;

    # yet another hack
    $text =~ s/(?<!\\)([\$\@])/\\$1/g;
    
    # unescape character class; this should probably
    # rather use qr to cope with \p{IsLower} and stuff
    local $_ = eval qq(qq($text));
    my $set = Set::IntSpan->new();

    # as above, this does not cope with escapes like
    # \p{IsLower} which it should...
    while (length) {
        s/^(.)-(.)//s or s/^(.)//s;
        my $range = join'-',map{ord}grep{defined}($1,$2);
        $set = $set->union(Set::IntSpan->new($range));
    }

#    print Dumper $set->spans;

    # Change the set such that only the right characters are
    # included
    $set = $set->diff($xmlout);

    # if only one character is left...        
    if ($set->cardinality == 1 and !$neg) {
        return esc [$set->spans]->[0][0];
    }
    
    # if no characters are left...
    if (!$set->spans) {
        $neg = !$neg;
        $set = $xmlin;
    }
    
    # make the new character class
    my $class = $neg ? '^' : '';
    foreach ($set->spans) {
        my($min,$max) = @{$_};
        $class .= $min==$max?esc$min:esc($min).'-'.esc($max);
    }
    
    return "[$class]";
}

sub verbatim {
    my $chunk = shift;
    my $text;
    
    if ($chunk->type eq 'text') {
        $text = $chunk->text;
    } else {
        $text = $chunk->string;
    }

    $text;
}

sub escape {
    join'',map{esc ord}split//,verbatim(shift);
}

sub group {
    "("
}

sub gclose {
    ")"
}

#######################################################################
# Public
#

sub re_pl2schema {
    my $regex = shift;
    my %options = @_;
    my $parser = YAPE::Regex->new($regex);

    my $new = "";
    my $i = -1;
    my %anchors;
    while (my $chunk = $parser->next) {
        ++$i;
        if ($chunk->type eq 'anchor' and $chunk->string =~ /^([\^\$])$/) {
            $anchors{$i} = $1;
            next;
        }

        #print Dumper $chunk;
        #print "  --- $new (". $chunk->quant .") ---\n\n";
        
        my $sub = $handler{$chunk->type};
        croak 'Chunks of type "' . $chunk->type . '" not supported'
            unless defined $sub;

        $new .= $sub->($chunk);
        $new .= $chunk->quant if $chunk->can('quant') and
                $sub != \&noop;
    }
    
    if (not($anchors{1} and $anchors{1} eq '^')) {
        $new = ".*$new" if $options{unanchor};
    }

    if (not($anchors{$i-1} and $anchors{$i-1} eq '$')) {
        $new = "$new.*" if $options{unanchor};
    }
    
    # leading ^
    delete $anchors{1};
    
    # trailing $
    delete $anchors{$i-1};
    
    croak 'Chunks of type "anchor" not supported'
     if keys %anchors;
    
    return $new;
}

#package main;
#print Regexp::Transform::XMLSchema::re_pl2schema('\cM');

1;

__END__

=head1 NAME

Regexp::Transform::XMLSchema - Transform Perl Regex to W3C XML Schema Regex

=head1 SYNOPSIS

  use Regexp::Transform::XMLSchema 're_pl2xmlschema';
  print re_pl2xmlschema(qr/^(?:[^\x00-\x1F]+?)/);

=head1 DESCRIPTION

Regexp::Transform::XMLSchema helps to convert Perl regular expressions to
XML Schema regular expressions by removing minor syntactic differences
in a Perl regex so it can be used in XML Schema. The module does not
attempt to convert advanced features available in Perl to XML Schema.

This module makes the following transformations:

=over 2

=item Removal of disallowed characters

XML 1.0 disallows use of certain Unicode characters and XML Schema has
no escape mechanism to circumvent this shortcoming. Expressions like
/[^\x00-\x1F]/ thus need to be rewritten to something where the U+0000
and U+001F characters do not occur, e.g. /[\x20-\x{10FFFF}]/. This
module does this by assuming the string the expression is matched
against will not contain any disallowed character and rewrites it with
characters that are allowed.

=item Non-greedy sub-expressions

XML Schema does not support non-greedy expressions like in /\d+?\w/;
as XML Schema does not support capturing sub-expressions either, such
expressions are written to use greedy sub-expressions which always
match the same strings.

=item Non-capturing sub-expressions

XML Schema doesn ot support non-capturing sub-expressions like /(?:x)/;
these are rewritten to use capturing sub-expressions instead (which
makes no difference in XML Schema as it does not support capturing).

=item 'x' modifier

A Regular expression with the /foo bar/x modifier is rewritten to an
expression that does not use the modifier and does not contain the
whitespace that would be ignored due to the modifier.

=item Comment patterns

Comment patterns like /(?#text)/ are removed from the expression as
XML Schema does not support such a feature and it makes no difference
to whether a string matches the expression.

=item Escape sequences

XML Schema supports only single character escpaes for its meta characters
and escapes for Unicode character classes and categories. This module
should ensure that the escape sequences are properly converted and all
characters in the resulting expression correctly escaped. This has not
been thoroughly tested yet.

=item ^ and $ anchors

XML Schema does not support the ^ and $ anchors; at the beginning and end
of the regular expression these are ignored; the C<unanchor> option can be
used to ensure that unanchored expressions will remain unanchored when used
in XML Schema (which always assumes /^$regex$/).

=back

=head1 FUNCTIONS

=over 2

=item re_pl2xmlschema( $regex [, @options ] )

The function takes a regular expression to be parsed using YAPE::Regex;
for most unsupported features in the expression the function croaks. If
the expression contains only supported features the result is a string
representing the expression in a way that is compatible with XML Schema.

The following options are available:

=over 4

=item unanchor => bool

XML Schema does not support anchors and always implies anchors at the
beginning and the end of the expression; if C<unanchor> is set to a true
value C<.*> will be added at the beginning and/or end of the expression
to ensure the semantics of the expressions will be maintained without
further post-processing of the result. This is off by default and has no
effect if the input expression is anchored.

=back

=back

=head1 EXPORTS

The re_pl2xmlschema function is exported upon request. The module does
not export any symbols by default.

=head1 UNICODE CONSIDERATIONS

As yet the module takes no special steps to ensure proper handling of
Unicode. Input is expected to be UTF-8 encoded and output should be
UTF-8 encoded aswell. Whether the UTF-8 flag is set on the result depends
on whether Perl upgrades the strings involved.

Character class references like \w behave in Perl differently depending
on the current locale and whether strings have the UTF-8 flag set; this
module pays no special attention to this issue and simply copies these
references verbatim into the result.

=head1 LIMITATIONS

The module does not properly support the following features:

  * msi Modifiers are ignored (!), for x see above
  * ^ and $ meta characters
  * \x{....} outside character classes
  * \C, \p, \P, \X, \b, \B, \A, \Z, \z, \G
  * POSIX character class syntax
  * Extended Patterns other than (?:) and (?#)
  * Backreferences

Future versions of this module might remove some of these limitations,
e.g., the case-insensitivity modifier could be supported by replacing
single characters by alternations of their upper- and lowercase variants.
Lack of \x{....} support outside character classes is due to a bug in
YAPE::Regex which will hopefully be addressed soon. There might be other
limitations not listed here. Patches welcome.

=head1 BUGS

Other then the limitations cited above the module does not handle well
the case where a disallowed character occurs as literal. It's too eager
to fix character classes, e.g. [\x00-\x{10ffff}] should be fixed to e.g.
[\x09\x0a\x0d\x20-\x{10ffff}] while the current result is significantly
longer. Escape handling is not well-tested. There is no test suite in
fact, which is another bug. For [[:ascii:]] it should croak but does not.
The expressions are wrapped inside (...) even though they should not be.
If no disallowed characters appear in character classes, it should not
touch them at all; currently e.g. [aa] will be reduced to [a] which isn't
bad but not the goal of the module.

=head1 SEE ALSO

  * http://rt.cpan.org/NoAuth/Bugs.html?Dist=Regex-Transform-XMLSchema
  * http://www.w3.org/TR/xmlschema-2/#regexs
  * YAPE::Regex

=head1 AUTHOR AND COPYRIGHT

  Copyright (c) 2006 Bjoern Hoehrmann <bjoern@hoehrmann.de>.
  This module is licensed under the same terms as Perl itself.

=cut
