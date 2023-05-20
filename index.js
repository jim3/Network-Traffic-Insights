const fs = require("fs/promises");
const dotenv = require("dotenv");
dotenv.config();

// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= //

class PacketAnalyzer {
    constructor() {
        this.data = this.data;
    }

    // =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= //

    async readData() {
        try {
            const jsonstr = await fs.readFile("wireshark.json", "utf8");
            const obj = await JSON.parse(jsonstr);
            this.data = obj;
        } catch (err) {
            console.error(err);
        }
        return this.data;
    }

    // =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= //

    async httpLocations() {
        const filteredSets = this.data.filter(
            (set) =>
                set.hasOwnProperty("_source") && set._source.layers.hasOwnProperty("ssdp")
        );

        const httpServerSet = new Set();
        const httpLocationSet = new Set();

        filteredSets.forEach((set) => {
            const ssdp = set._source.layers.ssdp;
            if (ssdp["http.server"]) {
                httpServerSet.add(ssdp["http.server"]);
            }
            if (ssdp["http.location"]) {
                httpLocationSet.add(ssdp["http.location"]);
            }
        });

        const httpServer = [...httpServerSet];
        const httpLocation = [...httpLocationSet];

        console.log("HTTP Server:");
        console.log(httpServer);

        console.log("HTTP Location:");
        console.log(httpLocation);
    }

    // =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= //

    async ipAddr() {
        const filteredSets = this.data.filter(
            (set) =>
                set.hasOwnProperty("_source") && set._source.layers.hasOwnProperty("ip")
        );

        const ipSrcSet = new Set();
        const ipDstSet = new Set();

        filteredSets.forEach((set) => {
            const ip = set._source.layers.ip;
            if (ip["ip.src"]) {
                ipSrcSet.add(ip["ip.src"]);
            }
            if (ip["ip.dst"]) {
                ipDstSet.add(ip["ip.dst"]);
            }
        });

        const ipSrc = [...ipSrcSet];
        const ipDst = [...ipDstSet];

        console.log("IP Source:");
        console.log(ipSrc);

        console.log("IP Dest:");
        console.log(ipDst);

        // Make API calls for each IP address
        const baseURL = "https://api.ip2location.io/";
        const apiKey = process.env.API_KEY;
        const format = "json";

        const getIPDetails = async (ipAddress) => {
            const url = `${baseURL}?key=${apiKey}&ip=${ipAddress}&format=${format}`;
            const response = await fetch(url);
            const data = await response.json();
            console.log(`IP Address: ${ipAddress}`);
            console.log(`City: ${data.city_name}`);
            console.log(`State: ${data.region_name}`);
            console.log(`Country: ${data.country_name}`);

            return data;
        };

        const ipDetails = await Promise.all(ipSrc.map((ip) => getIPDetails(ip)));
        console.log(ipDetails);
    }

    // =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= //

    async macAddr() {
        const filteredSets = this.data.filter(
            (set) =>
                set.hasOwnProperty("_source") && set._source.layers.hasOwnProperty("eth")
        );

        const ethSrcSet = new Set();
        const ethDstSet = new Set();

        filteredSets.forEach((set) => {
            const eth = set._source.layers.eth;
            if (eth["eth.src"]) {
                ethSrcSet.add(eth["eth.src"]);
            }
            if (eth["eth.dst"]) {
                ethDstSet.add(eth["eth.dst"]);
            }
        });

        const ethSrc = [...ethSrcSet];
        const ethDst = [...ethDstSet];

        console.log("Ethernet Source:");
        console.log(ethSrc);

        console.log("Ethernet Dest:");
        console.log(ethDst);
    }
}

// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= //

// main function
const main = async () => {
    // create a new instance of PacketAnalyzer
    const packetAnalyzer = new PacketAnalyzer();

    // read the data from the JSON file and print out the data
    const data = await packetAnalyzer.readData("wireshark.json");
    console.dir(data, { depth: null });

    // get the HTTP server and location and print out the data
    const httpLocations = await packetAnalyzer.httpLocations();
    console.dir(httpLocations, { depth: null });

    // get the IP addresses and print out the data
    const ipAddr = await packetAnalyzer.ipAddr();
    console.dir(ipAddr, { depth: null });

    // get the MAC addresses and print out the data
    const macAddr = await packetAnalyzer.macAddr();
    console.dir(macAddr, { depth: null });

    return 0;
};

main();
