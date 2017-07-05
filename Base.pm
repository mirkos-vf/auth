use utf8;

package Auth::Base;
use strict;
use warnings;
use FindBin;
use Try::Tiny;
use Crypt::SaltedHash;
use lib "$FindBin::Bin/../";
# TODO: завсимость от текущей схумы БД
use ORM::DB;

sub new {
    my ($class, $settings) = @_;
    my $self = {
        settings => $settings,
    };

    bless $self, $class;
    return $self;
}

=items authenticate_user

    Usually you'll want to let the built-in login handling code deal with authenticating users,
    but in case you need to do it yourself, this keyword accepts a username and password,
    and checks whether they are valid.

=cut

sub authenticate_user {
    my ( $self, $username, $password ) = @_;
    die 'username or password can''t be empty'
      if ( ($username eq '') && ($password eq '') );

    try {
        my $user = $self->get_user($username);
        return unless defined $user;
        my $mp = $self->match_password( $user->password, $password );
        $self->{logged_in} = ($mp eq '1') ? int $mp : int 0;
        $self->{logged_in_user} = $user;
    } catch {
        return undef;
    };
    return $self->{logged_in};
}

sub get_user {
    my ($self, $username) = @_;
    my $user = ORM::DB->db->resultset('User')->find(
        { name => "$username"}
    );
    return $user;
}

sub match_password {
    my ($self, $correct, $given) = @_;
    return Crypt::SaltedHash->validate($correct, $given);
}

=items logged_in_user

    If the user is logged in, returns a hashref of details about the currently logged-in user.
    What you get back will depend on the provider in use, but is flexible - for instance,
    if you're using the Database provider, all columns of the user table will be returned,
    so if you e.g. have columns containing the user's name and email address, you'll find them here.

=cut

sub logged_in_user {
    my ($self) = @_;
    if ( $self->{logged_in} ) {
        return $self->{logged_in_user};
    }
    return;
};

=items user_roles

    Returns a list of the currently logged-in user's roles.

=cut

sub user_roles {
    my ($self) = @_;
    my @roles = ORM::DB->db->resultset('user_role')->search(
        user_id =>  $self->{logged_in_user}->{id}
    );

    if (@roles->count) {
        return \@roles;
    }
    return;
}

=items user_has_role

    Allows you to manually check if the logged-in-user has a role you're interested in - for example:

    if (user_has_role('BeerDrinker')) {
        pour_beer();
    }

=cut

sub user_has_role {
    my ($self, $rolename) = @_;
    return;
}

=head1 AUTHOR

    Mirkos Vladislav, C<< https://www.facebook.com/profile.php?id=100001573272140 >>

=cut
1;
