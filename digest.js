var DigestAuth = function (username, password) {
    var auth = {
        nc: 0,
        uri: $digesturl,
        method: 'POST',
        status: 0,
        scheme: 'Digest',
        secret: password,
        username: username,
        headers: {}
    };

    var resetHeaders = function () {
        if (typeof (auth.headers) != "undefined") {
            delete auth.headers;
        }

        if (typeof (auth.digest) != "undefined") {
            delete auth.digest;
        }

        var ncx = '00000000' + ((++auth.nc) - 0).toString(16);
        ncx = ncx.substring(ncx.length - 8);

        auth.cnonce = (Math.random()).toString();

        auth.headers = {
            'uri': auth.uri,
            'nc': ncx,
            'debug': 0,
            'username': auth.username
        };
    };

    resetHeaders();

    $.ajax({
        url: $digestaskurl,
        type: 'GET',
        dataType: 'json',
        complete: function (result) {
            var header = result.getResponseHeader('WWW-Authenticate');
            parseAuthenticationResponse(header);
            return authenticate();
        },
    });

    var parseAuthenticationResponse = function (response) {
        var scre = /^\w+/;
        var scheme = scre.exec(response);
        auth.scheme = scheme[0];

        var nvre = /(\w+)=['"]([^'"]+)['"]/g;
        var pairs = response.match(nvre);

        var vre = /(\w+)=['"]([^'"]+)['"]/;
        var i = 0;
        for (; i < pairs.length; i++) {
            var v = vre.exec(pairs[i]);
            if (v) {
                // global headers object
                auth.headers[v[1]] = v[2];
            }
        }
    };

    var authenticate = function () {
        resetHeaders();
        $.ajax({
            url: auth.uri,
            cache: false,
            type: auth.method,

            beforeSend: function (client) {
                var header = buildAuthenticationRequest();
                if (header) {
                    client.setRequestHeader('Authorization', header);
                    return true;
                } else {
                    return false;
                }
            },
            success: function (result) {
                return true;
            },
            complete: function (result) {
                console.log(result);
            }
        });
    };

    var buildAuthenticationRequest = function () {
        var request = auth.scheme;
        delete auth.scheme;

        auth.headers.cnonce = digest(auth.cnonce);

        var comma = ' ';
        for (name in auth.headers) {
            request += comma + name + '="' + escape(auth.headers[name]) + '"';
            comma = ',';
        }

        // don't continue further if there is no algorithm yet.
        if (typeof (auth.headers.algorithm) == 'undefined') {
            return request;
        }

        var r = buildResponseHash();
        if (r) {
            request += comma + auth.mode + '="' + escape(r) + '"';
            return request;
        }

        return false;
    };

    var digest = function (s) {
        return MD5(s);
    };

    var buildResponseHash = function () {
        if (auth.headers.salt) {
            auth.secret = auth.secret + ':' + auth.headers.salt;
            delete auth.headers.salt;
        }
        if (auth.headers.migrate) {
            auth.secret = digest(auth.secret);
        }

        var A1 = digest(auth.headers.username + ':' + auth.headers.realm + ':' + auth.secret);
        delete auth.secret;
        var A2 = digest(auth.method + ':' + auth.headers.uri);
        var R = digest(A1 + ':'
            + auth.headers.nonce + ':'
            + auth.headers.nc + ':'
            + auth.headers.cnonce + ':'
            + auth.headers.qop + ':'
            + A2);
        return R;
    };
}
