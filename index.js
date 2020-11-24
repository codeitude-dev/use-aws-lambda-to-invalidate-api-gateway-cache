const https = require('https');
const crypto = require("crypto-js");
const SHA256 = require("crypto-js/sha256");
//This is not Base64, but just 'hex' funtion
const Base16 = require('crypto-js/enc-hex');
const HmacSHA256 = require('crypto-js/hmac-sha256');

var apiHost = 'news.highlights.com';
var cachedApi = '/news/highlights';
var serviceName = 'execute-api';
var algorithm = 'AWS4-HMAC-SHA256';

exports.handler = async (event) => {
    console.log("Path: " + event.path);
    //You can take required url from client also to make it dynamic
    //var cachedApi = event.path;
    var dateTime = new Date();
    //Not sure why but 'replaceAll' was not working, so I had to call 'replace' multiple times.
    //This formats date like: 20201115T231123Z
    var dateTimeInUTC = dateTime.toISOString().replace(/\-/, '').replace(/\-/, '')
        .replace(/:/, '').replace(/:/, '').replace(/(\.\d+)/, '');
    //Get only Date
    var date = dateTimeInUTC.split("T")[0];
    //Using process.env variable, we can get ACCESS KEY/SECRET KEY of IM Role assigned to Lambda
    var signingKey = getSignatureKey(process.env.AWS_SECRET_ACCESS_KEY, date,
        process.env.AWS_REGION, serviceName);
    var credentialScope = date + '/' + process.env.AWS_REGION + '/' + serviceName + '/aws4_request';
    //Headers name: Header value
    var canonicalHeaders = 'cache-control:max-age=0\nhost:' + apiHost + '\nx-amz-date:' + dateTimeInUTC + '\n';
    //Headers should be in lower case, headers in same order as are in above variable
    //These are just name of headers
    var signedHeaders = 'Cache-Control;host;X-Amz-Date'.toLowerCase();
    var canonicalRequest = 'GET\n' + productApi + '\n' + '\n' + canonicalHeaders + '\n' + signedHeaders + '\n' +
        Base16.stringify(SHA256(''));
    //console.log("Canonical Request: " + canonicalRequest);
    var hashedCanonicalRequest = Base16.stringify(SHA256(canonicalRequest));
    var stringToSign = algorithm + '\n' + dateTimeInUTC + '\n' + credentialScope + '\n' + hashedCanonicalRequest;
    //console.log("String To Sign: " + stringToSign);
    var signature = Base16.stringify(HmacSHA256(stringToSign, signingKey));
    var authorization = algorithm + ' Credential=' + process.env.AWS_ACCESS_KEY_ID +
        '/' + date + '/' + process.env.AWS_REGION + '/' + serviceName + '/aws4_request, SignedHeaders=' +
        signedHeaders + ', Signature=' + signature;

    let request = {
        hostname: apiHost,
        path: cachedApi,
        method: 'GET',
        headers: {
            'Cache-Control': 'max-age=0',
            'X-Amz-Date': dateTimeInUTC,
            'Authorization': authorization,
        }
    };
    //console.log('Auth Header: ' + request.headers['Authorization']);
    const apiResponse = await makeCall(request);

    const response = {
        statusCode: 200,
        body: apiResponse,
    };
    return response;
};

function getSignatureKey(key, dateStamp, regionName, serviceName) {
    var kDate = crypto.HmacSHA256(dateStamp, "AWS4" + key);
    var kRegion = crypto.HmacSHA256(regionName, kDate);
    var kService = crypto.HmacSHA256(serviceName, kRegion);
    var kSigning = crypto.HmacSHA256("aws4_request", kService);
    return kSigning;
}

function makeCall(options) {
    return new Promise(function (resolve, reject) {
        const request = https.request(options, (res) => {
            var finalData = '';
            res.on('data', function (data) {
                finalData += data;
            });
            res.on('end', function (data) {
                resolve(finalData);
            });
        });

        request.on('error', (e) => {
            reject(e);
        });

        request.write('');

        request.end();
    });
}