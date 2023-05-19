const fs = require("fs/promises");
const dotenv = require("dotenv");
dotenv.config();

// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= //

const readData = async () => {
    try {
        const jsonstr = await fs.readFile("wireshark.json", "utf8");
        const obj = await JSON.parse(jsonstr);
        return obj;
    } catch (err) {
        console.error(err);
    }
};

// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= //

const httpLocations = async () => {
    const myObj = await readData();

    const filteredSets = myObj.filter(
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
};

httpLocations();

// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= //

const ipAddr = async () => {
    const myObj = await readData();

    const filteredSets = myObj.filter(
        (set) => set.hasOwnProperty("_source") && set._source.layers.hasOwnProperty("ip")
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
    };

    ipSrc.forEach(async (ip) => {
        await getIPDetails(ip);
    });

    ipDst.forEach(async (ip) => {
        await getIPDetails(ip);
    });
};

ipAddr();

// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= //

const macAddr = async () => {
    const myObj = await readData();

    const filteredSets = myObj.filter(
        (set) => set.hasOwnProperty("_source") && set._source.layers.hasOwnProperty("eth")
    );

    const macSrcSet = new Set();
    const macDstSet = new Set();

    filteredSets.forEach((set) => {
        const eth = set._source.layers.eth;
        if (eth["eth.src"]) {
            macSrcSet.add(eth["eth.src"]);
        }
        if (eth["eth.dst"]) {
            macDstSet.add(eth["eth.dst"]);
        }
    });

    const macSrc = [...macSrcSet];
    const macDst = [...macDstSet];

    console.log("MAC Source:");
    console.log(macSrc);

    console.log("MAC Dest:");
    console.log(macDst);
};

macAddr();
