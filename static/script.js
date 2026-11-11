

function render_result(display, data) {
    display.textContent = typeof data === "string" ? data : JSON.stringify(data, null, 2);
}

function parse_response(response) {
    return response.text().then(text => {
        try {
            return JSON.parse(text);
        } catch {
            return text;
        }
    });
}

function whois_func() {

    var form = document.getElementById("whois_form");
    var map = document.getElementById("map");
    var display = document.getElementById("json");

    form.addEventListener("submit", async(e) => {

        e.preventDefault();
        var addr = document.getElementById("addr").value;
        
    
        fetch("/whois_scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({'addr': addr})
        })
            
            .then(response => {
                if (!response.ok) {
                    throw new Error(`${response.status}`);
                }
                return parse_response(response);
            })

            .then(data => {

                map.innerHTML = "";
                const displayed = {
                    "IP": data.ip,
                    "Continent": data.continent,
                    "Country": data.country,
                    "Region": data.region,
                    "City": data.city,
                    "Latitude": data.latitude,
                    "Longitude": data.longitude,
                    "Org": data.connection?.org,
                    "ISP": data.connection?.isp,
                    "Timezone": data.timezone?.id
                };
                
                render_result(display, displayed);

                if (data && typeof data === "object" && data.latitude != null && data.longitude != null) {
                    var iframe = document.createElement('iframe');
                    iframe.title = "IP location map";
                    iframe.style = 'border:0; width:100%; height:100%;';
                    iframe.src = `https://www.google.com/maps/embed/v1/place?key=[KEY_HIDDEN]&q=${data.latitude},${data.longitude}`;
                    iframe.allowFullscreen = true;
                    map.appendChild(iframe);
                }

                return data;
            })

            .catch(error => {
                console.log("Error: ", error);
                render_result(display, `Error: ${error.message}`);
                return error;
            });

        }
    )
};

function shodan_func() {

    var form = document.getElementById("shodan_form");
    var display = document.getElementById("json");

    form.addEventListener("submit", async(e) => {

        e.preventDefault();
        var addr = document.getElementById("IP").value;
        
    
        fetch("/shodan_scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({'IP': addr})
        })
            
            .then(response => {
                if (!response.ok) {
                    throw new Error(`${response.status}`);
                }

                return parse_response(response);
            })

            .then(data => {
                render_result(display, data);
                return data;
            })

            .catch(error => {
                console.log("Error: ", error);
                render_result(display, `Error: ${error.message}`);
                return error;
            });

        }
    )
};

function domain_func() {

    var form = document.getElementById("domain_form");
    var display = document.getElementById("json");

    form.addEventListener("submit", async(e) => {

        e.preventDefault();
        var domain = document.getElementById("domain").value;
        
    
        fetch("/domain_scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({'domain': domain})
        })
            
            .then(response => {
                if (!response.ok) {
                    throw new Error(`${response.status}`);
                }

                return parse_response(response);
            })

            .then(data => {
                render_result(display, data);
                return data;
            })

            .catch(error => {
                console.log("Error: ", error);
                render_result(display, `Error: ${error.message}`);
                return error;
            });

        }
    )
};

function malscan_func() {

    var form = document.getElementById("mal_form");
    var display = document.getElementById("json");

    form.addEventListener("submit", async(e) => {

        e.preventDefault();
        var link = document.getElementById("link").value;
        
    
        fetch("/malware_scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({'link': link})
        })
            
            .then(response => {
                if (!response.ok) {
                    throw new Error(`${response.status}`);
                }

                return parse_response(response);
            })

            .then(data => {
                render_result(display, data);
                return data;
            })

            .catch(error => {
                console.log("Error: ", error);
                render_result(display, `Error: ${error.message}`);
                return error;
            });

        }
    )
};


