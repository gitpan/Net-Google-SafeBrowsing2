package Net::Google::SafeBrowsing2::Sqlite;

use strict;
use warnings;

use base 'Net::Google::SafeBrowsing2::Storage';

use Carp;
use DBI;
use List::Util qw(first);


our $VERSION = '0.2';


=head1 NAME

Net::Google::SafeBrowsing2::Sqlite - Sqlite as back-end storage for the Google Safe Browsing v2 database

=head1 SYNOPSIS

  use Net::Google::SafeBrowsing2::Sqlite;

  my $storage = Net::Google::SafeBrowsing2::Sqlite->new(file => 'google-v2.db');
  ...
  $storage->close();

=head1 DESCRIPTION

This is an implementation of L<Net::Google::SafeBrowsing2::Storage> using Sqlite.

=cut


=head1 CONSTRUCTOR

=over 4

=head2 new()

Create a Net::Google::SafeBrowsing2::Sqlite object

  my $storage = Net::Google::SafeBrowsing2::Sqlite->new(file => 'google-v2.db');

Arguments

=over 4

=item file

Required. File to store the database.

=back


=back

=cut

sub new {
	my ($class, %args) = @_;

	my $self = { # default arguments
		file		=> 'gsb2.db',

		%args,
	};

	bless $self, $class or croak "Can't bless $class: $!";


	$self->init();

    return $self;
}

=head1 PUBLIC FUNCTIONS

=over 4

See L<Net::Google::SafeBrowsing2::Storage> for a complete list of public functions.

=head2 close()

Cleanup old full hashes, and close the connection to the database.

  my $storage->clode();


=cut

sub close {
	my ($self, %args) = @_;

	$self->{dbh}->do('DELETE FROM full_hashes WHERE timestamp < ?', { }, time() - Net::Google::SafeBrowsing2::FULL_HASH_TIME);

	$self->{dbh}->disconnect;
}

=back

=cut

sub init {
	my ($self, %args) = @_;

	$self->{dbh} = DBI->connect("dbi:SQLite:dbname=" . $self->{file}, "", "");

	my @tables = $self->{dbh}->tables;

	if (! defined first { $_ eq '"main"."updates"' || $_ eq '"updates"' } @tables) {
		$self->create_table_updates();
	}
	if (! defined first { $_ eq '"main"."a_chunks"' ||  $_ eq '"a_chunks"' } @tables) {
		$self->create_table_a_chunks();
	}
	if (! defined first { $_ eq '"main"."s_chunks"' || $_ eq '"s_chunks"' } @tables) { 
		$self->create_table_s_chunks();
	}
	if (! defined first { $_ eq '"main"."full_hashes"' || $_ eq '"full_hashes"' } @tables) {
		$self->create_table_full_hashes();
	}
	if (! defined first { $_ eq '"main"."full_hashes_errors"' || $_ eq '"full_hashes_errors"' } @tables) { 
		$self->create_table_full_hashes_errors();
	}
	if (! defined first { $_ eq '"main"."mac_keys"' || $_ eq '"mac_keys"' } @tables) { 
		$self->create_table_mac_keys();
	}
}


sub create_table_updates {
	my ($self, %args) = @_;

	my $schema = qq{	
		CREATE TABLE updates (
			last INTEGER DEFAULT 0,
			wait INTEGER DEFAULT 1800,
			errors INTEGER DEFAULT 0,
			list TEXT
		);
	}; # Need to handle errors

	$self->{dbh}->do($schema);
}

sub create_table_a_chunks {
	my ($self, %args) = @_;

	my $schema = qq{
		CREATE TABLE a_chunks (
			hostkey TEXT,
			prefix TEXT,
			num INTEGER,
			list TEXT
		);
	};

	$self->{dbh}->do($schema);

	my $index = qq{
		CREATE INDEX a_chunks_hostkey ON a_chunks (
			hostkey
		);
	};
	$self->{dbh}->do($index);

	$index = qq{
		CREATE INDEX a_chunks_num_list ON a_chunks (
			num,
			list
		);
	};
	$self->{dbh}->do($index);
}

sub create_table_s_chunks {
	my ($self, %args) = @_;

	my $schema = qq{
		CREATE TABLE s_chunks (
			hostkey TEXT,
			prefix TEXT,
			num INTEGER,
			add_num INTEGER,
			list TEXT
		);
	};

	$self->{dbh}->do($schema);

	my $index = qq{
		CREATE INDEX s_chunks_hostkey ON s_chunks (
			hostkey
		);
	};
	$self->{dbh}->do($index);

	$index = qq{
		CREATE INDEX s_chunks_num ON s_chunks (
			num
		);
	};
	$self->{dbh}->do($index);
}

sub create_table_full_hashes {
	my ($self, %args) = @_;

	my $schema = qq{
		CREATE TABLE full_hashes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			num INTEGER,
			hash TEXT,
			list TEXT,
			timestamp INTEGER
		);
	};

	$self->{dbh}->do($schema);

	my $index = qq{
		CREATE UNIQUE INDEX hash ON full_hashes (
			num,
			hash,
			list
		);
	};
	$self->{dbh}->do($index);
}

sub create_table_full_hashes_errors {
	my ($self, %args) = @_;

	my $schema = qq{
		CREATE TABLE full_hashes_errors (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			errors INTEGER,
			prefix TEXT,
			timestamp INTEGER
		);
	};

	$self->{dbh}->do($schema);
}

sub create_table_mac_keys{
	my ($self, %args) = @_;

	my $schema = qq{
		CREATE TABLE mac_keys (
			client_key TEXT Default '',
			wrapped_key TEXT Default ''
		);
	};

	$self->{dbh}->do($schema);
}


sub add_chunks {
	my ($self, %args) 	= @_;
	my $type			= $args{type}		|| 'a';
	my $chunknum		= $args{chunknum}	|| 0;
	my $chunks			= $args{chunks}		|| [];
	my $list			= $args{'list'}		|| '';

	if ($type eq 's') {
		$self->add_chunks_s(chunknum => $chunknum, chunks => $chunks, list => $list);
	}
	elsif ($type eq 'a') {
		$self->add_chunks_a(chunknum => $chunknum, chunks => $chunks, list => $list);
	}
}

sub add_chunks_s {
	my ($self, %args) 	= @_;
	my $chunknum		= $args{chunknum}	|| 0;
	my $chunks			= $args{chunks}		|| [];
	my $list			= $args{'list'}		|| '';

	my $sth = $self->{dbh}->prepare('INSERT INTO s_chunks (hostkey, prefix, num, add_num, list) VALUES (?, ?, ?, ?, ?)');

	foreach my $chunk (@$chunks) {
		$sth->execute( $chunk->{host}, $chunk->{prefix}, $chunknum, $chunk->{add_chunknum}, $list );
	}
}

sub add_chunks_a {
	my ($self, %args) 	= @_;
	my $chunknum		= $args{chunknum}	|| 0;
	my $chunks			= $args{chunks}		|| [];
	my $list			= $args{'list'}		|| '';

	my $sth = $self->{dbh}->prepare('INSERT INTO a_chunks (hostkey, prefix, num, list) VALUES (?, ?, ?, ?)');

	foreach my $chunk (@$chunks) {
		$sth->execute( $chunk->{host}, $chunk->{prefix}, $chunknum, $list );
	}

	if (scalar @$chunks == 0) { # keep empty chunks
		$sth->execute( '', '', $chunknum, $list );
	}
}


sub get_add_chunks {
	my ($self, %args) = @_;
	my $hostkey			= $args{hostkey}	|| '';
# 	my $list			= $args{'list'}		|| '';

	my @list = ();
# 	my $rows = $self->{dbh}->selectall_arrayref("SELECT * FROM a_chunks WHERE hostkey = ? AND list = ?", { Slice => {} }, $hostkey, $list);
	my $rows = $self->{dbh}->selectall_arrayref("SELECT * FROM a_chunks WHERE hostkey = ?", { Slice => {} }, $hostkey);

	foreach my $row (@$rows) {
		push(@list, { chunknum => $row->{num}, prefix => $row->{prefix}, list => $row->{list} });
	}

	return @list;
}

sub get_sub_chunks {
	my ($self, %args) = @_;
	my $hostkey			= $args{hostkey}	|| '';
# 	my $list			= $args{'list'}		|| '';

	my @list = ();
# 	my $rows = $self->{dbh}->selectall_arrayref("SELECT * FROM s_chunks WHERE hostkey = ? AND list = ?", { Slice => {} }, $hostkey, $list);
	my $rows = $self->{dbh}->selectall_arrayref("SELECT * FROM s_chunks WHERE hostkey = ?", { Slice => {} }, $hostkey);

	foreach my $row (@$rows) {
		push(@list, { chunknum => $row->{num}, prefix => $row->{prefix}, addchunknum => $row->{add_num}, list => $row->{list}  });
	}

	return @list;
}

sub get_add_chunks_nums {
	my ($self, %args) 	= @_;
	my $list			= $args{'list'}		|| '';
	
	my @list = ();
	my $rows = $self->{dbh}->selectall_arrayref("SELECT DISTINCT(num) FROM a_chunks WHERE list = ? ORDER BY num ASC", { Slice => {} }, $list);
	foreach my $row (@$rows) {
		push(@list, $row->{num});
	}

	return @list;
}

sub get_sub_chunks_nums {
	my ($self, %args) 	= @_;
	my $list			= $args{'list'}		|| '';
	
	my @list = ();
	my $rows = $self->{dbh}->selectall_arrayref("SELECT DISTINCT(num) FROM s_chunks WHERE list = ? ORDER BY num ASC", { Slice => {} }, $list);
	foreach my $row (@$rows) {
		push(@list, $row->{num});
	}

	return @list;
}


sub delete_add_ckunks {
	my ($self, %args) 	= @_;
	my $chunknums		= $args{chunknums}	|| [];
	my $list			= $args{'list'}		|| '';

	my $sth = $self->{dbh}->prepare("DELETE FROM a_chunks WHERE num = ? AND list = ?");

	foreach my $num (@$chunknums) {
		$sth->execute($num, $list);
	}
}


sub delete_sub_ckunks {
	my ($self, %args) = @_;
	my $chunknums		= $args{chunknums}	|| [];
	my $list			= $args{'list'}		|| '';

	my $sth = $self->{dbh}->prepare("DELETE FROM s_chunks WHERE num = ? AND list = ?");

	foreach my $num (@$chunknums) {
		$sth->execute($num, $list);
	}


}

sub get_full_hashes {
	my ($self, %args) = @_;
	my $chunknum		= $args{chunknum}	|| 0;
	my $timestamp		= $args{timestamp}	|| 0;
	my $list			= $args{list}		|| '';

	my @hashes = ();

	my $rows = $self->{dbh}->selectall_arrayref("SELECT hash FROM full_hashes WHERE timestamp >= ? AND num = ? AND list = ?", { Slice => {} }, $timestamp, $chunknum, $list);
	foreach my $row (@$rows) {
		push(@hashes, $row->{hash});
	}

	return @hashes;
}


sub updated {
	my ($self, %args) 	= @_;
	my $time			= $args{'time'}	|| time;
	my $wait			= $args{'wait'}	|| 1800;
	my $list			= $args{'list'}	|| '';

	if ($self->last_update(list => $list)->{'time'} == 0) {
		$self->{dbh}->do("INSERT INTO updates (last, wait, errors, list) VALUES (?, ?, 0, ?)", undef, $time, $wait, $list);
	}
	else {
		$self->{dbh}->do("UPDATE updates SET last = ?, wait = ?, errors = 0 WHERE list = ?", undef, $time, $wait, $list);
	}
}

sub update_error {
	my ($self, %args) 	= @_;
	my $time			= $args{'time'}	|| time;
	my $list			= $args{'list'}	|| '';
	my $wait			= $args{'wait'}	|| 60;
	my $errors			= $args{errors}	|| 1;

	if ($self->last_update(list => $list)->{'time'} == 0) {
		$self->{dbh}->do("INSERT INTO updates (last, wait, errors, list) VALUES (?, ?, ?, ?)", undef, $time, $wait, $errors, $list);
	}
	else {
		$self->{dbh}->do("UPDATE updates SET last = ?, wait = ?, errors = ?, list = ? WHERE 1", undef, $time, $wait, $errors, $list);
	}
}

sub last_update {
	my ($self, %args) 	= @_;
	my $list			= $args{'list'}	|| '';

	my $rows = $self->{dbh}->selectall_arrayref("SELECT last, wait, errors FROM updates WHERE list = ? LIMIT 1", { Slice => {} }, $list);

	foreach my $row (@$rows) {
		return {'time' => $row->{'last'} || 0, 'wait' => $row->{'wait'} || 1800, errors	=> $row->{'errors'} || 0};
	}

	return {'time' => 0, 'wait' => 1800};
}

sub add_full_hashes {
	my ($self, %args) 	= @_;
	my $timestamp		= $args{timestamp}		|| time();
	my $full_hashes		= $args{full_hashes}	|| [];

	foreach my $hash (@$full_hashes) {
		$self->{dbh}->do("INSERT OR REPLACE INTO full_hashes (num, hash, list, timestamp) VALUES (?, ?, ?, ?)", { }, $hash->{chunknum}, $hash->{hash}, $hash->{list}, $timestamp);
	}

}

sub delete_full_hashes {
	my ($self, %args) 	= @_;
	my $chunknums		= $args{chunknums}	|| [];
	my $list			= $args{list}			|| croak "Missing list name\n";

	my $sth = $self->{dbh}->prepare("DELETE FROM full_hashes WHERE num = ? AND list = ?");

	foreach my $num (@$chunknums) {
		$sth->execute($num, $list);
	}
}

sub full_hash_error {
	my ($self, %args) 	= @_;
	my $timestamp		= $args{timestamp}	|| time();
	my $prefix			= $args{prefix}		|| '';

	my $rows = $self->{dbh}->selectall_arrayref("SELECT id, errors FROM full_hashes_errors WHERE prefix = ? LIMIT 1", { Slice => {} }, $prefix);

	if (scalar @$rows == 0) {
		$self->{dbh}->do("INSERT INTO full_hashes_errors (prefix, errors, timestamp) VALUES (?, 1, ?)", { }, $prefix, $timestamp);
	}
	else {
		my $errors = $rows->[0]->{errors} + 1;
		$self->{dbh}->do("UPDATE full_hashes_errors SET errors = ?, timestamp = ? WHERE id = ?", $errors, $timestamp, $rows->[0]->{id});
	}
}

sub full_hash_ok {
	my ($self, %args) 	= @_;
	my $timestamp		= $args{timestamp}	|| time();
	my $prefix			= $args{prefix}		|| '';

	my $rows = $self->{dbh}->selectall_arrayref("SELECT id, errors FROM full_hashes_errors WHERE prefix = ? AND errors > 0 LIMIT 1", { Slice => {} }, $prefix);

	if (scalar @$rows > 0) {
		$self->{dbh}->do("UPDATE full_hashes_errors SET errors = 0, timestamp = ? WHERE id = ?", $timestamp, $rows->[0]->{id});
		$self->{dbh}->do("DELETE FROM full_hashes_errors WHERE id = ?", $timestamp, $rows->[0]->{id});
	}
}

sub get_full_hash_error {
	my ($self, %args) 	= @_;
	my $prefix			= $args{prefix}		|| '';

	my $rows = $self->{dbh}->selectall_arrayref("SELECT timestamp, errors FROM full_hashes_errors WHERE prefix = ? LIMIT 1", { Slice => {} }, $prefix);
	
	if (scalar @$rows == 0) {
		return undef;
	}
	else {
		return $rows->[0];
	}
}

sub get_mac_keys {
	my ($self, %args) 	= @_;


	my $rows = $self->{dbh}->selectall_arrayref("SELECT client_key, wrapped_key FROM mac_keys LIMIT 1", { Slice => {} });

	if (scalar @$rows == 0) {
		return { client_key => '', wrapped_key => '' };
	}
	else {
		return $rows->[0];
	}
}

sub add_mac_keys {
	my ($self, %args) 	= @_;
	my $client_key		= $args{client_key}		|| '';
	my $wrapped_key		= $args{wrapped_key}	|| '';


	$self->delete_mac_keys();

	$self->{dbh}->do("INSERT INTO mac_keys (client_key, wrapped_key) VALUES (?, ?)", { }, $client_key, $wrapped_key);

}

sub delete_mac_keys {
	my ($self, %args) 	= @_;

	$self->{dbh}->do("DELETE FROM mac_keys WHERE 1");
}

=head1 CHANGELOG

=over 4

=item 0.2

Add close() function to clean up old full hashes, and to close the connection to the database cleanly.

Add table and function to store and retrieve the Message Authentication Code (MAC) key.

In some environments, the module was trying to re-create exising tables. Fixed (Thank you to  Luis Alberto Perez).

=back


=head1 SEE ALSO

See L<Net::Google::SafeBrowsing2> for handling Google Safe Browsing v2.

See L<Net::Google::SafeBrowsing2::Storage> for the list of public functions.

Google Safe Browsing v2 API: L<http://code.google.com/apis/safebrowsing/developers_guide_v2.html>


=head1 AUTHOR

Julien Sobrier, E<lt>jsobrier@zscaler.com<gt> or E<lt>julien@sobrier.netE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by Julien Sobrier

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.


=cut

1;