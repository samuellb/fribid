// ==UserScript==
// @name FriBID NPAPI Compatibility
// @description FriBID compatibility script for pages using BankID through NPAPI
// @namespace https://fribid.se/
// @version 1.0.4
// @run-at document-start
// @grant none
// @match https://*/*
// ==/UserScript==

/*

  Copyright (c) 2014 Samuel Lidén Borell <samuel@kodafritt.se>
 
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the 'Software'), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
  
  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.
  
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.

*/

function main() {
    if (!window.navigator.plugins['Nexus Personal']) {
        FriBID_NPAPI_Compat = {
            // TODO we might need to use HTTPS
            'REQ_URL': 'http://127.0.0.1:20048/FriBID_NPAPI_Request',
            
            'TYPE_AUTH': 'application/x-personal-authentication',
            'TYPE_REGUTIL': 'application/x-personal-regutil',
            'TYPE_SIGN': 'application/x-personal-signer2',
            'TYPE_OLDSIGN': 'application/x-personal-signer',
            'TYPE_VER': 'application/x-personal-version',
            'TYPE_WEBADMIN': 'application/x-personal-webadmin',
            
            'hasParam': function(obj, name) {
                if (typeof name != 'string') return false;
                name = name.toLowerCase();
                
                if (!obj.FriBID_NPAPI_Compat_Params) {
                    this.setDefaults(obj);
                }
                return name in obj.FriBID_NPAPI_Compat_Params;
            },
            
            'setParam': function(obj, name, value) {
                if (typeof name != 'string') return this.setLastError(obj, 8004);
                name = name.toLowerCase();
                
                if (!obj.FriBID_NPAPI_Compat_Params) {
                    this.setDefaults(obj);
                }
                obj.FriBID_NPAPI_Compat_Params[name] = value;
                return 0;
            },
            
            'getParam': function(obj, name) {
                if (typeof name != 'string') return this.setLastError(obj, 8004);
                name = name.toLowerCase();
                
                if (!obj.FriBID_NPAPI_Compat_Params) {
                    this.setDefaults(obj);
                }
                return obj.FriBID_NPAPI_Compat_Params[name];
            },
            
            'setDefaults': function(obj) {
                params = {};
                switch (obj.type) {
                    case this.TYPE_AUTH:
                        params['challenge'] = '';
                        params['onlyacceptmru'] = 'false';
                        params['policys'] = '';
                        params['servertime'] = '';
                        params['signature'] = '';
                        params['subjects'] = '';
                        break;
                    case this.TYPE_SIGN:
                        params['nonce'] = '';
                        params['nonvisibledata'] = '';
                        params['onlyacceptmru'] = 'false';
                        params['policys'] = '';
                        params['servertime'] = '';
                        params['signature'] = '';
                        params['subjects'] = '';
                        params['textcharacterencoding'] = '';
                        params['texttobesigned'] = '';
                        break;
                    case this.TYPE_REGUTIL:
                        params['subjectdn'] = '';
                        params['onetimepassword'] = '';
                        params['keysize'] = '';
                        params['minlen'] = '';
                        params['minchars'] = '';
                        params['mindigits'] = '';
                        params['maxlen'] = '';
                        params['keyusage'] = '';
                        params['rfc2797cmcoid'] = 'true';
                        break;
                }
                obj.FriBID_NPAPI_Compat_Params = params;
            },
            
            'hasRequiredParams': function (obj) {
                switch (obj.type) {
                    case this.TYPE_AUTH:
                        return this.getParam(obj, 'challenge') != '';
                    case this.TYPE_SIGN:
                        return this.getParam(obj, 'nonce') != '' && this.getParam(obj, 'texttobesigned') != '';
                    default:
                        throw new Exception('called on wrong type of <object>: '+obj.type);
                }
            },
            
            'performAction': function(obj, actionName) {
                if (typeof actionName != 'string') return this.setLastError(obj, 8008);
                actionName = actionName.toLowerCase();
                
                if (obj.type == this.TYPE_AUTH) {
                    if (actionName != 'authenticate') return this.setLastError(obj, 8008);
                } else if (obj.type == this.TYPE_SIGN) {
                    if (actionName != 'sign') return this.setLastError(obj, 8008);
                } else {
                    throw new Exception('called on wrong type of <object>: '+obj.type);
                }
                
                if (!this.hasRequiredParams(obj)) {
                    return this.setLastError(obj, 8016);
                }
                
                var resp = this.sendPluginRequest(actionName, obj.FriBID_NPAPI_Compat_Params);
                if (typeof resp == 'int') {
                    return resp; // Failed to send request
                } else {
                    this.updateParams(obj, resp.params);
                    return this.setLastError(obj, resp.errorCode);
                }
            },
            
            'getLastError': function(obj) {
                var errnum = obj.FriBID_NPAPI_Compat_LastError;
                return errnum ? errnum : 0;
            },
            
            'setLastError': function(obj, errnum) {
                obj.FriBID_NPAPI_Compat_LastError = errnum;
                return errnum;
            },
            
            'updateParams': function(obj, params) {
                for (var name in params) {
                    if (params.hasOwnProperty(name)) {
                        obj.FriBID_NPAPI_Compat_Params[name] = params[name];
                    }
                }
            },
            
            'sendPluginRequest': function(requestType, params) {
                var data = 'requestType='+requestType;
                for (var name in params) {
                    if (params.hasOwnProperty(name)) {
                        // All parameter values should be Base64 encoded or integers
                        data += '&' + name + '=' + escape(params[name]);
                    }
                }
                
                var req = new XMLHttpRequest();
                req.timeout = 0;
                req.open('POST', this.REQ_URL, false);
                req.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
                try {
                    req.send(data);
                } catch (e) {
                    alert("Failed to connect to FriBID npcompatsrv.\n\nAn exception ocurred: "+e);
                    throw e;
                }
                if (req.status == 200) {
                    try {
                        return JSON.parse(req.responseText);
                    } catch (e) {
                        return 3;
                    }
                } else {
                    alert("Failed to connect to FriBID npcompatsrv.\n\nError status: "+req.status);
                    return 2;
                }
            }
        };
        
        // TODO add all properties to these objects
        window.navigator.plugins['Nexus Personal'] = { };
        window.navigator.mimeTypes[FriBID_NPAPI_Compat.TYPE_AUTH] = { 'enabledPlugin': true };
        window.navigator.mimeTypes[FriBID_NPAPI_Compat.TYPE_REGUTIL] = { 'enabledPlugin': true };
        window.navigator.mimeTypes[FriBID_NPAPI_Compat.TYPE_SIGN] = { 'enabledPlugin': true };
        window.navigator.mimeTypes[FriBID_NPAPI_Compat.TYPE_OLDSIGN] = { 'enabledPlugin': true };
        window.navigator.mimeTypes[FriBID_NPAPI_Compat.TYPE_VER] = { 'enabledPlugin': true };
        window.navigator.mimeTypes[FriBID_NPAPI_Compat.TYPE_WEBUTIL] = { 'enabledPlugin': true };

        window.HTMLObjectElement.prototype.GetVersion = function() {
            var fribid = FriBID_NPAPI_Compat;
            if (this.type == fribid.TYPE_VER) {
                var bestbefore = Math.ceil(Date.now()/1000 + 29*24*3600);
                return 'Personal=4.15.0.14&libai_so=4.15.0.14&libP11_so=4.15.0.14&libtokenapi_so=4.15.0.14&libCardSiemens_so=4.15.0.14&libCardSetec_so=4.15.0.14&libCardPrisma_so=4.15.0.14&libBranding_so=4.15.0.14&libplugins_so=4.15.0.14&personal_bin=4.15.0.14&platform=linux&distribution=unknown&os_version=unknown&best_before='+bestbefore+'&';
            } else {
                throw new Exception('xxx');
            }
        };

        window.HTMLObjectElement.prototype.SetParam = function(name, value) {
            var fribid = FriBID_NPAPI_Compat;
            if (this.type == fribid.TYPE_AUTH || this.type == fribid.TYPE_SIGN) {
                if (fribid.hasParam(this, name)) {
                    return fribid.setLastError(this, fribid.setParam(this, name, value));
                } else {
                    return fribid.setLastError(this, 8004);
                }
            } else if (this.type == fribid.TYPE_REGUTIL) {
                if (fribid.hasParam(this, name)) {
                    return fribid.setLastError(this, fribid.setParam(this, name, value));
                } else {
                    return fribid.setLastError(this, 640);
                }
            } else {
                throw new Exception('xxx');
            }
        };

        window.HTMLObjectElement.prototype.GetParam = function(name) {
            var fribid = FriBID_NPAPI_Compat;
            if (this.type == fribid.TYPE_AUTH || this.type == fribid.TYPE_SIGN) {
                if (fribid.hasParam(this, name)) {
                    var val = fribid.getParam(this, name);
                    fribid.setLastError(this, 0);
                    return val;
                } else {
                    return fribid.setLastError(this, 8004);
                }
            } else if (this.type == fribid.TYPE_REGUTIL) {
                if (fribid.hasParam(this, name)) {
                    var val = fribid.getParam(this, name);
                    fribid.setLastError(this, 0);
                    return val;
                } else {
                    return fribid.setLastError(this, 640);
                }
            } else {
                throw new Exception('xxx');
            }
        };
        
        window.HTMLObjectElement.prototype.Reset = function() {
            var fribid = FriBID_NPAPI_Compat;
            if (this.type == fribid.TYPE_AUTH || this.type == fribid.TYPE_SIGN) {
                fribid.setDefaults(this);
                return fribid.setLastError(this, 0);
            } else {
                throw new Exception('xxx');
            }
        };
        
        window.HTMLObjectElement.prototype.GetLastError = function() {
            var fribid = FriBID_NPAPI_Compat;
            if (this.type == fribid.TYPE_AUTH || this.type == fribid.TYPE_SIGN ||
                this.type == fribid.TYPE_REGUTIL || this.type == fribid.TYPE_WEBADMIN) {
                return fribid.getLastError(this);
            } else {
                throw new Exception('xxx');
            }
        };

        window.HTMLObjectElement.prototype.PerformAction = function(actionName) {
            var fribid = FriBID_NPAPI_Compat;
            if (this.type == fribid.TYPE_AUTH || this.type == fribid.TYPE_SIGN) {
                return fribid.performAction(this, actionName);
            } else if (this.type == fribid.TYPE_WEBADMIN) {
                return fribid.setLastError(this, 8008);
            } else {
                throw new Exception('xxx');
            }
        };
    }
}

var s = document.createElement("script");
s.appendChild(document.createTextNode('('+main+')();'));
(document.body || document.head || document.documentElement).appendChild(s);




