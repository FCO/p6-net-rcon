unit package Net::RCON;

use experimental :pack;

enum SERVERDATA is export (
        RESPONSE_VALUE => 0,
        AUTH_RESPONSE => 2,
        EXECCOMMAND => 2,
        AUTH => 3,
);

sub connect(Str :$host = "localhost", Int :$port = 27015, Str :$password) is export {
    my $connection = IO::Socket::INET.new: :$host, :$port;

    authenticate :$connection, :$password;
    return $connection;
}

sub authenticate(:$connection, Str :$password) {
    _raw_send :$connection, :packet-type(SERVERDATA::AUTH), :message($password);
    my $response = receive $connection, SERVERDATA::AUTH_RESPONSE;

    die "Could not authenticate against the RCON server." without $response;
}

sub send(:$connection, SERVERDATA :$packet-type, Str :$message) is export {
    _raw_send :$connection, :$packet-type, :$message;
    my $response = receive $connection, SERVERDATA::RESPONSE_VALUE;
    die "Received a bad response from the RCON server." without $response;

    return $response;
}

sub _raw_send(:$connection, SERVERDATA :$packet-type, Str :$message) {
    my $payload = pack("VV", 1, $packet-type) ~ $message.encode ~ pack("xx");
    $payload = pack("V", $payload.bytes) ~ $payload;

    $connection.write($payload);
}

sub receive($connection, SERVERDATA $expected-type) {
    my $response = $connection.recv: 4096, :bin;
    my ($response-size, $response-id, $packet-type, $response-body) = $response.unpack("VVVa*");

    if ($response-id == 1 && $packet-type == $expected-type && $response-size >= 10 && $response-size <= 4096) {
        return $response-body;
    }

    return;
}
