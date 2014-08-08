
"use strict;"

/*
    UW Shibboleth Passport Authentication Module

    This module exposes a passport Strategy object that is pre-configured to
    work with the UW's Shibboleth identity provider (IdP). To use this, you 
    must register your server with the UW IdP, and you can use the 
    metadataRoute() method below to provide the metadata necessary for 
    registration via the standard metadata url (urls.metadata).

    author: Dave Stearns

    Modified for use at The University of Arizona by Gary Windham
*/

const passport = require('passport');
const saml = require('passport-saml');
const util = require('util');

const uaIdPCert = 'MIIFGTCCBAGgAwIBAgICAacwDQYJKoZIhvcNAQEFBQAwVjELMAkGA1UEBhMCVVMxHDAaBgNVBAoTE0luQ29tbW9uIEZlZGVyYXRpb24xKTAnBgNVBAMTIEluQ29tbW9uIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTA4MDkwMjE4MTI1NVoXDTEwMDkwMzE4MTI1NVowITEfMB0GA1UEAxMWc2hpYmJvbGV0aC5hcml6b25hLmVkdTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAqBuPxEj2NG2GqJjg7Zw+4mu4XRPa0ufssw3cIASt3IEgufn42asdZI8wzKhWT05byJb4tceUxuL28Um1gQBCVX6zembBwyqD90xsk7OS0YUEs6b48/QRlp2/hgpB4hTRRbFQmb5DCWYB/uL+v5tJuNFSet9lRGsoT0lirQezkL0CAwEAAaOCAqgwggKkMA4GA1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUzw3Z4FLbvZT827kCD8nEamfZjokwfgYDVR0jBHcwdYAUky3IYRitY+ObZbOd3Y2TuufKY0WhWqRYMFYxCzAJBgNVBAYTAlVTMRwwGgYDVQQKExNJbkNvbW1vbiBGZWRlcmF0aW9uMSkwJwYDVQQDEyBJbkNvbW1vbiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eYIBADCBsgYIKwYBBQUHAQEEgaUwgaIwTwYIKwYBBQUHMAKGQ2h0dHA6Ly9pbmNvbW1vbmNhMS5pbmNvbW1vbmZlZGVyYXRpb24ub3JnL2JyaWRnZS9jZXJ0cy9jYS1jZXJ0cy5wN2IwTwYIKwYBBQUHMAKGQ2h0dHA6Ly9pbmNvbW1vbmNhMi5pbmNvbW1vbmZlZGVyYXRpb24ub3JnL2JyaWRnZS9jZXJ0cy9jYS1jZXJ0cy5wN2IwgY0GA1UdHwSBhTCBgjA/oD2gO4Y5aHR0cDovL2luY29tbW9uY3JsMS5pbmNvbW1vbmZlZGVyYXRpb24ub3JnL2NybC9lZWNybHMuY3JsMD+gPaA7hjlodHRwOi8vaW5jb21tb25jcmwyLmluY29tbW9uZmVkZXJhdGlvbi5vcmcvY3JsL2VlY3Jscy5jcmwwXgYDVR0gBFcwVTBTBgsrBgEEAa4jAQQBATBEMEIGCCsGAQUFBwIBFjZodHRwOi8vaW5jb21tb25jYS5pbmNvbW1vbmZlZGVyYXRpb24ub3JnL3ByYWN0aWNlcy5wZGYwIQYDVR0RBBowGIIWc2hpYmJvbGV0aC5hcml6b25hLmVkdTANBgkqhkiG9w0BAQUFAAOCAQEAxJZo4qDSuwBWODXdbOuHwo5v34tHZR6OSjPDGxDJAyNcqVaTICmkq7a1ZIRoga0ju3UcFtcC97sQGMElKMCK8eLdHZ28c/Cpenl/HSrUQMXBtc6Vs+66TsDGSwLnfb17Fo24u1uzOH8UrRfO9zOV8jpt/XwvkNQhgOFpMHX/n4uuvAZdrsxuh24ZsUoGKA3CmzE2p/F1Fthazm/YvrKZOAjQS1kKNw7z7p3MXpnfwZa+lc+oAEgXdCcHL18b4omzMYpvra8DeM0kT40bZQp415GZvJTO+66U36H6oeKUcPyHbO0t35B2yNPTEldklNs+9cbUeA7pKr2ed6JHgScoZA==';
const uaIdPEntryPoint = 'https://shibboleth.arizona.edu/idp/profile/SAML2/Redirect/SSO';
const strategyName = 'uasaml';

//standard login, callback, logout, and meta-data URLs
//these will be exposed from module.exports so that
//clients can refer to them
//the metadata one in particular is important to get right
//as the auto-regisration process requires that exact URL
const urls = {
    metadata: '/Shibboleth.sso/Metadata',
    uaLogoutUrl: 'https://shibboleth.arizona.edu/cgi-bin/logout.pl'
};

//export the urls map
module.exports.urls = urls;

//map of possible profile attributes and what name
//we should give them on the resulting user object
//add to this with other attrs if you request them
const profileAttrs = {
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.6': 'Shib-eppn',
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.9': 'Shib-affiliation',
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.1': 'Shib-unscoped-affiliation',
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.7': 'Shib-entitlement',
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.10': 'Shib-persistent-id',
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.5': 'Shib-primary-affiliation',
    'urn:oid:2.5.4.3': 'Shib-cn',
    'urn:oid:2.5.4.4': 'Shib-sn',
    'urn:oid:2.5.4.42': 'Shib-givenName',
    'urn:oid:2.16.840.1.113730.3.1.4': 'Shib-employeeType',
    'urn:oid:0.9.2342.19200300.100.1.1': 'Shib-uid',
    'urn:oid:0.9.2342.19200300.100.1.3': 'Shib-mail',
    'urn:oid:1.3.6.1.4.1.5923.1.5.1.1': 'Shib-isMemberOf',
    'urn:oid:1.3.6.1.4.1.5643.10.0.1': 'Shib-uaId',
    'urn:oid:1.3.6.1.4.1.5643.10.0.49': 'Shib-dateOfBirth',
    'urn:oid:1.3.6.1.4.1.5643.10.0.56': 'Shib-isoNumber',
    'urn:oid:1.3.6.1.4.1.5643.10.0.61': 'Shib-emplId',
    'urn:oid:1.3.6.1.4.1.5643.10.0.64': 'Shib-preferredCn',
    'urn:oid:1.3.6.1.4.1.5643.10.0.65': 'Shib-preferredSn',
    'urn:oid:1.3.6.1.4.1.5643.10.0.66': 'Shib-preferredGivenname',
    'urn:oid:1.3.6.1.4.1.5643.10.0.91': 'Shib-studentAdmitCareerProgramPlan',
    'urn:oid:1.3.6.1.4.1.5643.10.0.96': 'Shib-studentAPDesc',
    'urn:oid:1.3.6.1.4.1.5643.10.0.77': 'Shib-studentCareerProgramPlan',
    'urn:oid:1.3.6.1.4.1.5643.10.0.78': 'Shib-studentPrimaryCareerProgramPlan',
    'urn:oid:1.3.6.1.4.1.5643.10.0.55': 'Shib-studentHonorsActive',
    'urn:oid:1.3.6.1.4.1.5643.10.0.31': 'Shib-studentInfoReleaseCode',
    'urn:oid:1.3.6.1.4.1.5643.10.0.80': 'Shib-studentStatus',
    'urn:oid:1.3.6.1.4.1.5643.10.0.81': 'Shib-studentStatusHistory',
    'urn:oid:1.3.6.1.4.1.5643.10.0.13': 'Shib-employeeBldgName',
    'urn:oid:1.3.6.1.4.1.5643.10.0.14': 'Shib-employeeBldgNum',
    'urn:oid:1.3.6.1.4.1.5643.10.0.67': 'Shib-employeeCity',
    'urn:oid:1.3.6.1.4.1.5643.10.0.85': 'Shib-employeeFTE',
    'urn:oid:1.3.6.1.4.1.5643.10.0.87': 'Shib-employeeHireDate',
    'urn:oid:1.3.6.1.4.1.5643.10.0.53': 'Shib-employeeIncumbentPosition',
    'urn:oid:1.3.6.1.4.1.5643.10.0.42': 'Shib-employeeIsFerpaTrained',
    'urn:oid:1.3.6.1.4.1.5643.10.0.110': 'Shib-employeeOfficialOrg',
    'urn:oid:1.3.6.1.4.1.5643.10.0.111': 'Shib-employeeOfficialOrgName',
    'urn:oid:1.3.6.1.4.1.5643.10.0.74': 'Shib-employeeOrgReporting',
    'urn:oid:1.3.6.1.4.1.5643.10.0.17': 'Shib-employeePhone',
    'urn:oid:1.3.6.1.4.1.5643.10.0.12': 'Shib-employeePoBox',
    'urn:oid:1.3.6.1.4.1.5643.10.0.86': 'Shib-employeePositionFTE',
    'urn:oid:1.3.6.1.4.1.5643.10.0.54': 'Shib-employeePositionFunding',
    'urn:oid:1.3.6.1.4.1.5643.10.0.8': 'Shib-employeePrimaryDept',
    'urn:oid:1.3.6.1.4.1.5643.10.0.52': 'Shib-employeePrimaryDeptName',
    'urn:oid:1.3.6.1.4.1.5643.10.0.75': 'Shib-employeePrimaryOrgReporting',
    'urn:oid:1.3.6.1.4.1.5943.10.0.90': 'Shib-employeePrimaryTitle',
    'urn:oid:1.3.6.1.4.1.5643.10.0.94': 'Shib-employeeRetireeTitle',
    'urn:oid:1.3.6.1.4.1.5643.10.0.15': 'Shib-employeeRoomNum',
    'urn:oid:1.3.6.1.4.1.5643.10.0.10': 'Shib-employeeRosterDept',
    'urn:oid:1.3.6.1.4.1.5643.10.0.68': 'Shib-employeeState',
    'urn:oid:1.3.6.1.4.1.5643.10.0.4': 'Shib-employeeStatus',
    'urn:oid:1.3.6.1.4.1.5643.10.0.5': 'Shib-employeeStatusDate',
    'urn:oid:1.3.6.1.4.1.5643.10.0.70': 'Shib-employeeTotalAnnualRate',
    'urn:oid:1.3.6.1.4.1.5643.10.0.93': 'Shib-employeeTerminationReason',
    'urn:oid:1.3.6.1.4.1.5643.10.0.3': 'Shib-employeeTitle',
    'urn:oid:1.3.6.1.4.1.5643.10.0.69': 'Shib-employeeZip',
    'urn:oid:1.3.6.1.4.1.5643.10.0.104': 'Shib-dccPrimaryActionDate',
    'urn:oid:1.3.6.1.4.1.5643.10.0.102': 'Shib-dccPrimaryDept',
    'urn:oid:1.3.6.1.4.1.5643.10.0.103': 'Shib-dccPrimaryDeptName',
    'urn:oid:1.3.6.1.4.1.5643.10.0.105': 'Shib-dccPrimaryEndDate',
    'urn:oid:1.3.6.1.4.1.5643.10.0.106': 'Shib-dccPrimaryStatus',
    'urn:oid:1.3.6.1.4.1.5643.10.0.100': 'Shib-dccPrimaryTitle',
    'urn:oid:1.3.6.1.4.1.5643.10.0.101': 'Shib-dccPrimaryType',
    'urn:oid:1.3.6.1.4.1.5643.10.0.107': 'Shib-dccRelation'
};

function convertProfileToUser(profile) {
    var user = {};
    var niceName;
    var attr;
    for (attr in profile) {
        niceName = profileAttrs[attr];
        if (niceName !== undefined && profile[attr]) {
            user[niceName] = profile[attr];
        }
    }
    return user;    
}

/*
    Passport Strategy for UW Shibboleth Authentication
    This class extends passport-saml's Strategy, providing the necessary 
    options and handling the conversion of the returned profile into a 
    sensible user object.

    options should contain:
        entityId: your server's entity id,
        domain: your server's domain name,
        callbackUrl: login callback url (relative to domain),
        privateKey: your private key for signing requests (optional)
*/
function Strategy(options) {
    samlOptions = {
        entryPoint: uaIdPEntryPoint,
        cert: uaIdPCert,
        identifierFormat: null,
        issuer: options.entityId || options.domain,
        callbackUrl: 'https://' + options.domain + options.callbackUrl,
        decryptionPvk: options.privateKey,
        privateCert: options.privateKey,
        acceptedClockSkewMs: 180000
    };

    function verify(profile, done) {
        if (!profile)
            return done(new Error('Empty SAML profile returned!'));
        else {    
            user = convertProfileToUser(profile);
            if (user) {
                if ("authz" in options) {
                    authz = options["authz"](user);
                    if (!authz.status) {
                        return done(null, false, { message: authz.message });
                    }
                }
            }
            return done(null, user);
        }              
    }

    saml.Strategy.call(this, samlOptions, verify);
    this.name = strategyName;
}

util.inherits(Strategy, saml.Strategy);

//expose the Strategy
module.exports.Strategy = Strategy;

/*
    Route implementation for the standard Shibboleth metadata route
    usage:
        var uashib = require(...);
        var strategy = new uashib.Strategy({...});
        app.get(uashib.urls.metadata, uashib.metadataRoute(strategy, myPublicCert));
*/
module.exports.metadataRoute = function(strategy, publicCert) {
    return function(req, res) {
        res.type('application/xml');
        res.status(200).send(strategy.generateServiceProviderMetadata(publicCert));
    }
} //metadataRoute

/*
    Middleware for ensuring that the user has authenticated.
    You can use this in two different ways. If you pass this to
    app.use(), it will secure all routes added after that.
    Or you can use it selectively on routes that require authentication
    like so:
        app.get('/foo/bar', ensureAuth(loginUrl), function(req, res) {
            //route implementation
        });

    where loginUrl is the url to your login route where you call
    passport.authenticate()
*/
module.exports.ensureAuth = function(loginUrl) {
    return function(req, res, next) {
        if (req.isAuthenticated())
            return next();
        else {
            req.session.authRedirectUrl = req.url;
            res.redirect(loginUrl);
        }
    }
};

/*
    Middleware for redirecting back to the originally requested URL after
    a successful authentication. The ensureAuth() middleware above will
    capture the current URL in session state, and when your callback route
    is called, you can use this to get back to the originally-requested URL.
    usage:
        var uashib = require(...);
        var strategy = new uashib.Strategy({...});
        app.get('/login', passport.authenticate(strategy.name));
        app.post('/login/callback', passport.authenticate(strategy.name), uashib.backtoUrl());
        app.use(uashib.ensureAuth('/login'));
*/
module.exports.backToUrl = function(defaultUrl) {
    return function(req, res) {
        var url = req.session.authRedirectUrl;
        delete req.session.authRedirectUrl;
        res.redirect(url || defaultUrl || '/');
    }
};


