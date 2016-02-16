package Crypt::XTEA;

# ABSTRACT: Implementation of the eXtended Tiny Encryption Algorithm

use strict;
use warnings;
use utf8;

use Carp;
use List::Util qw(all);
use Scalar::Util::Numeric qw(isint);

# VERSION

require XSLoader;
XSLoader::load('Crypt::XTEA', $VERSION);

=head1 SYNOPSIS

   use Crypt::XTEA;
   use Crypt::CBC;

   my $xtea = Crypt::XTEA->new( $key );
   my $cbc = Crypt::CBC->new( -cipher => $xtea );

   my $text = 'The quick brown fox jumps over the lazy dog.';
   my $cipher_text = $cbc->encrypt( $text );

   my $plain_text = $cbc->decrypt( $cipher_text );

=head1 DESCRIPTION

In cryptography, XTEA (eXtended TEA) is a block cipher designed to correct weaknesses in TEA.
The cipher's designers were David Wheeler and Roger Needham of the Cambridge Computer Laboratory,
and the algorithm was presented in an unpublished technical report in 1997 (Needham and Wheeler, 1997).
It is not subject to any patents.

Like TEA, XTEA is a 64-bit block Feistel cipher with a 128-bit key and a suggested 64 Feistel rounds (i.e 32 cycles).
Crypt::XTEA uses the recommended value of 32 cycles by default.

This module implements XTEA encryption. It supports the Crypt::CBC interface, with the following functions.

=cut

my $ROUNDS = 32;
my $KEY_SIZE = 16;
my $ELEMENTS_IN_KEY = $KEY_SIZE / 4;
my $BLOCK_SIZE = 8;
my $ELEMENTS_IN_BLOCK = $BLOCK_SIZE / 4;

=method keysize

Returns the maximum XTEA key size, 16 bytes.

=cut

use constant keysize => $KEY_SIZE;

=method blocksize

Returns the XTEA block size, which is 8 bytes. This function exists so that Crypt::XTEA can work with Crypt::CBC.

=cut

use constant blocksize => $BLOCK_SIZE;

=method new

    my $xtea = Crypt::XTEA->new( $key, $rounds, little_endian => 0 );

This creates a new Crypt::XTEA object with the specified key.
The optional rounds parameter specifies the number of rounds of encryption to perform, and defaults to 32.
If the key is provided as a scalar string, it is split to a series of 4x big-endian 32-bit integers. If little-endian order is required instead, the optional little_endian key can be set to 1. This will also cause all blocks to be interpreted as 2x little-endian 32-bit integers.

=cut

sub new {
    my $class = shift;
    my $key = shift;
    my $rounds = shift // $ROUNDS;
    my %opts = (little_endian => 0, @_);
    my $xtea_key;
    croak( 'key is required' ) if not defined $key;
    if ( my $ref_of_key = ref( $key ) ) {
        croak( sprintf( 'key must be a %d-byte-long STRING or a reference of ARRAY', $KEY_SIZE ) ) if not $ref_of_key eq 'ARRAY';
        croak( sprintf( 'key must has %d elements if key is a reference of ARRAY', $ELEMENTS_IN_KEY ) ) if scalar( @{ $key } ) != $ELEMENTS_IN_KEY;
        croak( 'each element of key must be a 32bit Integer if key is a reference of ARRAY' ) if not all { isint( $_ ) != 0 } @{ $key };
        $xtea_key = $key;
    } else {
        croak( sprintf( 'key must be a %d-byte-long STRING or a reference of ARRAY', $KEY_SIZE ) ) if length $key != $KEY_SIZE;
        $xtea_key = key_setup($key, $opts{little_endian});
    }
    croak( 'rounds must be a positive NUMBER' ) if isint( $rounds ) != 1;
    my $self = {
        key => $xtea_key,
        rounds => $rounds,
        endianness => $opts{little_endian} ? 'V*' : 'N*',
    };
    bless $self, ref($class) || $class;
}

=method encrypt

    $cipher_text = $xtea->encrypt($plain_text);

Encrypts blocksize() bytes of $plain_text and returns the corresponding ciphertext.

=cut

sub encrypt {
    my $self = shift;
    my $plain_text = shift;
    croak( sprintf( 'plain_text block size must be %d bytes', $BLOCK_SIZE) ) if length($plain_text) != $BLOCK_SIZE;
    my @block = unpack $self->{endianness}, $plain_text;
    my $cipher_text_ref = $self->encrypt_block( \@block );
    return pack( $self->{endianness}, @{$cipher_text_ref} );
}

=method decrypt

    $plain_text = $xtea->decrypt($cipher_text);

Decrypts blocksize() bytes of $cipher_text and returns the corresponding plaintext.

=cut

sub decrypt {
    my $self = shift;
    my $cipher_text = shift;
    croak( sprintf( 'cipher_text size must be %d bytes', $BLOCK_SIZE) ) if length($cipher_text) != $BLOCK_SIZE;
    my @block = unpack $self->{endianness}, $cipher_text;
    my $plain_text_ref = $self->decrypt_block( \@block );
    return pack( $self->{endianness}, @{$plain_text_ref} );
}

sub encrypt_block {
    my $self = shift;
    my $block_ref = shift;
    my $key_ref = $self->{key};

    croak( sprintf( 'block must has %d elements', $ELEMENTS_IN_BLOCK ) ) if scalar( @{ $block_ref } ) != $ELEMENTS_IN_BLOCK;
    croak( sprintf( 'key must has %d elements', $ELEMENTS_IN_KEY ) ) if scalar( @{ $key_ref } ) != $ELEMENTS_IN_KEY;

    return $self->encrypt_block_in_c( $block_ref );
}

sub decrypt_block {
    my $self = shift;
    my $block_ref = shift;
    my $key_ref = $self->{key};

    croak( sprintf( 'block must has %d elements', $ELEMENTS_IN_BLOCK ) ) if scalar( @{ $block_ref } ) != $ELEMENTS_IN_BLOCK;
    croak( sprintf( 'key must has %d elements', $ELEMENTS_IN_KEY ) ) if scalar( @{ $key_ref } ) != $ELEMENTS_IN_KEY;

    return $self->decrypt_block_in_c( $block_ref );
}

sub key_setup {
    my $key_str = shift;
    my $endianness = (shift) ? 'V*' : 'N*';
    croak( sprintf( 'key must be %s bytes long', $KEY_SIZE ) ) if length( $key_str ) != $KEY_SIZE;
    my @xtea_key = unpack $endianness, $key_str;
    return \@xtea_key;
}

=head1 SEE ALSO

L<Crypt::CBC>

L<Crypt::XTEA_PP>

=cut

1;
