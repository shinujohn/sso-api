var express = require('express');
var session = require('express-session');
var cookieParser = require('cookie-parser');
var adal = require('adal-node');
var crypto = require('crypto');
var path = require('path');
var proxySecurity = require('./ProxySecurity');

/*
 * General configuration
 */
// app name: aadonesc-api
var config = {
    tenant: 'aadonesc.onmicrosoft.com',
    loginUrl: 'https://login.windows.net',
    clientId: '8b0b489f-0f9d-4bdb-9756-5e51f1386a74',
    clientSecret: '7AkMFdUG9xuKjdsxJznoqZ/D5vpCVbpgkEWNnUF6ppQ=',
    port: 8788,
    redirectUrl: 'http://localhost:8788/auth/token' ,
    resource: '00000002-0000-0000-c000-000000000000',
    azureUrl: 'https://login.windows.net/{{tenant}}/oauth2/authorize?response_type=code&client_id={{clientId}}&redirect_uri={{redirectUri}}&resource={{resource}}',
    webUrl: 'http://localhost:8787'
};

var server = express();
server.use(cookieParser());
server.use(session({
    name: 'session',
    secret: 'd26fb56d-aa1f-a892-4722-0788557021ba',
    rolling : true, 
    resave: false,
    saveUninitialized: true
}));

// CORS
server.use(function crossOrigin(req, res, next) {
    res.header("Access-Control-Allow-Origin", (process.env.webUrl || config.webUrl));
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, oscauth, Cache-Control');
    
    return next();
});

/*
 * Azure AD login
 */
var AuthenticationContext = adal.AuthenticationContext;
var loginUrl = (process.env.loginUrl || config.loginUrl) + '/' + (process.env.tenant || config.tenant);
var redirectUri = (process.env.redirectUrl || config.redirectUrl);
var resource = (process.env.resource || config.resource);

var azureUrl = (process.env.azureUrl || config.azureUrl);

azureUrl = azureUrl.replace('{{tenant}}', (process.env.tenant || config.tenant))
            .replace('{{clientId}}', (process.env.clientId || config.clientId))
            .replace('{{redirectUri}}', redirectUri)
            .replace('{{resource}}', resource);


/*
 * Login request handler - redirects to the Azure AD signin page 
 */
server.get('/auth/login', function (req, res) {
    crypto.randomBytes(48, function (ex, buf) {
        var state = buf.toString('base64').replace(/\//g, '_').replace(/\+/g, '-');
        
        res.cookie('state', state);
        res.redirect(azureUrl + '&state=' + state);
    });
    
});


/*
 * Logout request handler 
 */
server.get('/auth/logout', function (req, res) {
    req.session.destroy(function (err) {
        console.error(err);
    });

    res.clearCookie('auth');
    res.clearCookie('state');
    res.redirect(process.env.webUrl || config.webUrl);
});

/*
 * Handler to recieve the token from Azure AD once successfully authenticated
 */
server.get('/auth/token', function (req, res) {
    
    // TODO:
    if (req.cookies.state !== req.query.state) {
        res.send('error: state does not match');
    }
    
    proxySecurity.getAccessToken(req.query.code).then(function (accessToken) {
        res.cookie('auth', accessToken);
        res.redirect((process.env.webUrl || config.webUrl));
    }).catch(function (err) {
        res.send(err);
    });
 
});

/*
 * Middleware to validate user context/authentication status
 */
server.use(function (req, res, next) {
    if (req.cookies.auth && proxySecurity.validateToken(req.cookies.auth)) {
        next();
    }
    else {
        res.redirect('/auth/login');
    }
});

/* 
 * Returns information about the current user
 */
server.get('/api/user', function (req, res) {
    res.send(parseBase64String(req.cookies.auth.split('.')[0]));
});

server.listen(process.env.port || 8788, function () {
    console.log('API started');
});


// private utility
function parseBase64String(sourceString) {
    return (new Buffer(sourceString, 'base64')).toString('ascii');
}