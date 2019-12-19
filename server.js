/*
 * GeoIP Microservice
 */
var https = require('https'),
    helmet = require('helmet'),
    express = require("express"),
    bodyParser = require('body-parser'),
    maxmind = require('maxmind'),
    apiPrefix = '/api/v1';

// Load Maxmind City database
try { 
    var cityLookup = maxmind.open(__dirname + '/GeoLite2-City.mmdb');
} catch (err) { 
    if (err) { console.log(err); } 
}

// Load Maxmind Country database
try {
    var countryLookup = maxmind.open(__dirname + '/GeoLite2-Country.mmdb');
} catch (err) { 
    if (err) { console.log(err); }
}

// =============== Server Setup ===============

// Setup server
var port = 443;
var app = express();
var route = express.Router();

// Configure our App
app.use( apiPrefix, route );
route.use(bodyParser.json());
route.use(bodyParser.urlencoded({ extended: true }));

// Setup Helmet
app.use(helmet());
// Kill all caching
app.use(helmet.noCache() );
// Set strict transport security
app.use(helmet.hsts({ maxAge: 7776000000, force: true }) );
// Disable the express server header
app.disable('x-powered-by');

// =============== Routing ===============

// Route all Traffic through https, order is important (this should be the first route)
route.all('*', function(req, res, next){
    if (req.secure) {
        return next();
    };
    res.redirect(`https://geoip.exampledomain.com:${port}${req.url}`);
});

// These are the main ip information retrieval endpoints of our service
//route.post('/get/ipcountry', auth, getIpCountry);
route.post('/get/all', auth, getIpCity);
route.get('/get/all', auth, getIpCity);
route.use( '/', healthCheck);

// =============== Begin Implementation ===============

function healthCheck(req, res) {
    res.sendStatus(200);
    //console.log(req.body);
    res.end();
}

function getIpCity ( req, res ) {

    var ipaddr = req.query.ipaddr || req.body.ipaddr;
	console.log( 'Request:', ipaddr ); 
    
	if (isIpAddress(ipaddr) === true) {
        var result = cityLookup.get(ipaddr),
            resObj = {};

        // Paving over all the wild underbrush...
        try {
            if (typeof result.location !== 'undefined') {
                resObj.global_pos = {};
                resObj.global_pos.accuracy_radius_km = result.location.accuracy_radius;
                resObj.global_pos.latitude = result.location.latitude;
                resObj.global_pos.longitude = result.location.longitude;
                resObj.global_pos.time_zone = result.location.time_zone;
            }
        } catch(err) { 
            if (err) console.error(err);
            resObj.global_pos = false;
        }

        try {
            if (typeof result.continent !== 'undefined') {
                resObj.continent = {};
                resObj.continent.name = result.continent.names.en;
            }
        } catch(err) { 
            if (err) console.error(err);
            resObj.continent = false;
        }
            
        try {
            if (typeof result.country !== 'undefined') {
                resObj.country = {};
                resObj.country.iso_code = (typeof result.country.iso_code) !== 'undefined' ? result.country.iso_code : false;
                resObj.country.name = (typeof result.country.names.en) !== 'undefined' ? result.country.names.en : false;
            }
        } catch(err) { 
            if (err) console.error(err);
            resObj.country = false;
        }

        try {
            if (typeof result.registered_country !== 'undefined') {
                resObj.registered_country = {};
                resObj.registered_country.iso_code = (typeof result.registered_country.iso_code) !== 'undefined' ? result.registered_country.iso_code : false;
                resObj.registered_country.name = (typeof result.registered_country.names.en) !== 'undefined' ? result.registered_country.names.en : false;
            }
        } catch(err) { 
            if (err) console.error(err);
            resObj.registered_country = false;
        }

        try {
            if (typeof result.subdivisions !== 'undefined') {
                resObj.subdivisions = {};
                resObj.subdivisions.iso_code = (typeof result.subdivisions[0]['iso_code']) !== 'undefined' ? result.subdivisions[0]['iso_code'] : false;
                resObj.subdivisions.name = (typeof result.subdivisions[0]['names']['en']) !== 'undefined' ? result.subdivisions[0]['names']['en'] : false;
            }
        } catch(err) { 
            if (err) console.error(err);
            resObj.subdivisions = false;
        }

        try {
            if (typeof result.postal !== 'undefined') {
                resObj.postal_code = ((typeof result.postal.code) !== 'undefined') ? result.postal.code : false;
            }
        } catch(err) { 
            if (err) console.error(err);
            resObj.postal = false;
        }

        try {
            if (typeof result.city !== 'undefined') {
                resObj.city = {};
                resObj.city.name = (typeof result.city.names.en) !== 'undefined' ? result.city.names.en : false;
            }
        } catch(err) { 
            if (err) console.error(err);
            resObj.city = false;
        }

        res.append('Content-Type', 'application/json');
        res.status(200).json(resObj);
    } else {
        var errMessage = "Supplied value is not a valid IPv4 or IPv6 address.";
        res.status(400).json({error: errMessage});
    }
}

function isIpAddress ( ipAddrString ) {
    return (maxmind.validate(ipAddrString) === true) ? true : false;
}

function auth(req, res, cb) {
    // -----------------------------------------------------------------------
    // Authentication
    const auth = { login: getCreds('user'), password: getCreds('pass') };
    const b64auth = (req.headers.authorization || '').split(' ')[1] || '';
    const [login, password] = new Buffer(b64auth, 'base64').toString().split(':');
    // Check that the login / pass are present
    if (!login || !password || login !== auth.login || password !== auth.password) {
        res.set('WWW-Authenticate', 'Basic realm="Authorization Required"');
        res.status(401).send('Unauthorized Access Denied!');
        return;
    } else {
        return cb();
    }
}

function getCreds(token) {
    if (token === 'user') {
        return 'usernameX';
    }
    if ( token === 'pass' ) {
        return 'd9643eb685ec7595a6cf4df2ee66ec57978846ce';
    }
}

// =============== SSL Certificates ===============
function getSSLCert() {
    var sslCert =
        `-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIJAMYJltRQ+3RIMA0GCSqGSIb3DQEBCwUAMBwxGjAYBgNV
BAMMEXNhZ2UudmVub20zNjAuY29tMB4XDTE2MDQyMDAzNDQ1N1oXDTI2MDQxODAz
NDQ1N1owHDEaMBgGA1UEAwwRc2FnZS52ZW5vbTM2MC5jb20wggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDYiw1ocWM2irjhoItx2dk1kKL74uTvyuwbN6Q8
d0rEg3ksNj8u9V5gEpYMi/SbGQA2LyqxUo+FFWgUUfShKf8gUcEodtPqL3qhJYsp
CRZl8X2R1F9tiBuRdPG+cwIL8hLR6Jb4NKmbw1MA8zCgC6sl4Fx4bd4u8kybGYW2
kzGRmcJBt27r8+Zx4SFPMWDfblWzPXq91/IqiabrFufD34y0D5uihcYRKtFPDeek
T/YLxLNaZHPiDY7LfB188ugBpgh5Qmc7OP1JnBJEERBn0w5uBFd6742w1q7AONv/
ELL67vFjIGFjc73mUvEjkAkvJJbav5eABDjazratSeo5QwdlAgMBAAGjUDBOMB0G
A1UdDgQWBBQzx82hq08bUJrmLKb/fYjLx2q7GDAfBgNVHSMEGDAWgBQzx82hq08b
UJrmLKb/fYjLx2q7GDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDQ
Pfj4IS84SV5smdaSWU0kUacjXI5A6+g+WpD3849f3iOhIUEtUF5TgWS+zb4qnmrB
BrGWeU3+IXUDDuQbwDZ3Xhbh1MwBQqvbw0oUsAXOtvcaHPsq5Y348FxKQmagiGEP
MNaPPaD5QR8BGekTlXdTtW0atow3aCUv72uFjXtFF2E2MWlMscGZ9JvceAvGOpXX
9/kzMpk1SldVpK2ydMRvCyfS35Dny7Nk69Y8hwINKNhpAiDioV8Moz1DFk0RF/+Y
py/3tHqG12IDFTPKxJ71eiEW22ew0qIhK+dQKll0PtsZ0qzizTsHTaegbuBMRvYz
IreQ+yV5jHOdES+xf/wR
-----END CERTIFICATE-----
`;
    return new Buffer(sslCert, "binary");
}

function getSSLKey() {
    var sslKey =
        `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDYiw1ocWM2irjh
oItx2dk1kKL74uTvyuwbN6Q8d0rEg3ksNj8u9V5gEpYMi/SbGQA2LyqxUo+FFWgU
UfShKf8gUcEodtPqL3qhJYspCRZl8X2R1F9tiBuRdPG+cwIL8hLR6Jb4NKmbw1MA
8zCgC6sl4Fx4bd4u8kybGYW2kzGRmcJBt27r8+Zx4SFPMWDfblWzPXq91/Iqiabr
FufD34y0D5uihcYRKtFPDeekT/YLxLNaZHPiDY7LfB188ugBpgh5Qmc7OP1JnBJE
ERBn0w5uBFd6742w1q7AONv/ELL67vFjIGFjc73mUvEjkAkvJJbav5eABDjazrat
Seo5QwdlAgMBAAECggEAcwHPOjRWhCZDMRoqVWplUWyjE3KbMrwsj/wKT07wN9S3
64JYJmGNIStd5AYFAMbTdPOyEgGOVhlbcMdiTKJYbNre4tXRkSRsVd/xu/amnbgX
f/cyQ6MxORzKM+MzKBMGadPFMsgNeLvRfsSqg6YO3Qv/MLrxcS+g/hMdEC22+uOb
vizU8vafNZWcIJB4mbTvKQNL/yOD8liKXkdJ/8djWi6MWHzEkhlWNpWvGRSoAj87
3hQdl5NyhdVXF1jhbcuFdjQOtt7KHJlv7n1uZ7j96JpROQ7ivE6SYPPNPJBsYKAP
9ZlCO8JUgNpPXmgyXvoKnvensDJlYzuPaJT4mlM9tQKBgQDw1mHOmF4wIxw4vMWV
i8nsi0qeZmb9iljPxpO/N9akPwhxGgBWWpb9pw6jXKAbKBrgl4roM7dR1wO/BzuC
8qWeklQ1rtcOuJmVk7QHAGGjjePFxFP+i7Fx3m3+4ALX4X8H8L5m/GsRXVRiGM3H
fGx4l/qYqLH7fm8Hl7s7g6Ut9wKBgQDmLR2agMLrzEYGXXn85aWJeyDqqmSKO0sg
8yYvDFZRGP9hfuo7698OoqLew0tSL4E1gURL1fyNbBchlCiFb99jd/bQZDTpvSJ9
zrEvK4jw5Bykmup2oyk72xdB0jS0Xk/glFD9W+bgZI1wjQnQQ1tEKuiLQORchMga
bzeqfE8OgwKBgQCp3nxULNJaX5lbR4KRjWyaRFEYUqAX+snTm3vAptDlPnRk2fMc
9X6EYJ2Jih5/qRT0Ds9yInAN8Ht69M37+cvpgcqVpsGXZ4sknm6fdZxosP7UEjsw
UjWRXFL3L+exfyKLZjnWB/o44DxRiK80IkWb9Y5SuMH44l/L2jC8tIkAVwKBgC/6
xYn4PylhylL3Vz9VK11uEh14aT67P1zd8l6qRq/e8xUCnJbjAvsNAcBHm0LFbjyV
9oOMVnmwR14TgSLXgAw+7G7iBHmYmED7PcnkXEZCdooFVMxoFGdKsx1gUOYsJqBc
qkk1x/mMXENS0vHbqIGcJB8q5q82anPALS1Xfi87AoGBAIECfnmRg0MM1noSMYDE
psZ+D74HQ0ujS1RjIhULmcJlRAr6S1bIaQiEufSawr7vr67hQKaVVdQb1Po3A9EK
41Y43HPCvJbPHq/2KdGxDfmBUuvs+4mO+/97c1rgrxHipdrvapN+0ySFAVKfEvCf
RHACgxi7CLJdMjPj8gs3zU7B
-----END PRIVATE KEY-----
`;
    return new Buffer(sslKey, "binary");
}

// =============== Run Server ===============
var secureServer = https.createServer({ key: getSSLKey(), cert: getSSLCert() }, app)
    .listen( port, function () { console.log( 'GeoIP Secure Server listening on port ' + port ); });

