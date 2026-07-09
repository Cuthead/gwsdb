package geo

type place struct {
	city    string
	country string
}

// regionalCodes covers the 2-letter "regional" 1e100.net prefixes documented
// on the wiki. This list is necessarily incomplete -- Google does not publish
// it, so entries are added as they're observed in the wild.
var regionalCodes = map[string]place{
	"tb": {"Taipei", "Taiwan"},
	"tf": {"Taipei", "Taiwan"},
	"tg": {"Taipei", "Taiwan"},
}

// airportCodes maps IATA airport codes to the city/country Google's PTR
// naming convention associates them with. This is a best-effort table of
// airports known to host Google infrastructure (from public reporting and
// community documentation) plus common major-airport codes as a fallback --
// an unrecognized code simply renders without a resolved location.
var airportCodes = map[string]place{
	// United States
	"atl": {"Atlanta, GA", "United States"},
	"auz": {"Aurora, IL", "United States"},
	"bos": {"Boston, MA", "United States"},
	"ord": {"Chicago, IL", "United States"},
	"dfw": {"Dallas-Fort Worth, TX", "United States"},
	"den": {"Denver, CO", "United States"},
	"iad": {"Ashburn/Washington, VA", "United States"},
	"dls": {"The Dalles, OR", "United States"},
	"hou": {"Houston, TX", "United States"},
	"iah": {"Houston, TX", "United States"},
	"lax": {"Los Angeles, CA", "United States"},
	"lga": {"New York, NY", "United States"},
	"jfk": {"New York, NY", "United States"},
	"ewr": {"Newark, NJ", "United States"},
	"mia": {"Miami, FL", "United States"},
	"msp": {"Minneapolis, MN", "United States"},
	"nuq": {"Mountain View, CA", "United States"},
	"pao": {"Palo Alto, CA", "United States"},
	"sjc": {"San Jose, CA", "United States"},
	"sfo": {"San Francisco, CA", "United States"},
	"oak": {"Oakland, CA", "United States"},
	"sea": {"Seattle, WA", "United States"},
	"phx": {"Phoenix, AZ", "United States"},
	"slc": {"Salt Lake City, UT", "United States"},
	"stl": {"St. Louis, MO", "United States"},
	"pdx": {"Portland, OR", "United States"},
	"rfd": {"Rockford, IL", "United States"},
	"mci": {"Kansas City, MO", "United States"},
	"lhm": {"Council Bluffs, IA", "United States"},
	"cbf": {"Council Bluffs, IA", "United States"},
	"okc": {"Oklahoma City, OK", "United States"},
	"clt": {"Charlotte, NC", "United States"},
	"las": {"Las Vegas, NV", "United States"},

	// Europe
	"lhr": {"London", "United Kingdom"},
	"lcy": {"London", "United Kingdom"},
	"man": {"Manchester", "United Kingdom"},
	"dub": {"Dublin", "Ireland"},
	"ork": {"Cork", "Ireland"},
	"ams": {"Amsterdam/Eemshaven", "Netherlands"},
	"gro": {"Girona/Barcelona", "Spain"},
	"mad": {"Madrid", "Spain"},
	"fra": {"Frankfurt", "Germany"},
	"ber": {"Berlin", "Germany"},
	"muc": {"Munich", "Germany"},
	"mrs": {"Marseille/Saint-Ghislain", "Belgium/France"},
	"cdg": {"Paris", "France"},
	"mxp": {"Milan", "Italy"},
	"fco": {"Rome", "Italy"},
	"arn": {"Stockholm", "Sweden"},
	"osl": {"Oslo", "Norway"},
	"cph": {"Copenhagen", "Denmark"},
	"hel": {"Hamina/Helsinki", "Finland"},
	"waw": {"Warsaw", "Poland"},
	"vie": {"Vienna", "Austria"},
	"zrh": {"Zurich", "Switzerland"},
	"prg": {"Prague", "Czechia"},
	"buh": {"Bucharest", "Romania"},
	"otp": {"Bucharest", "Romania"},

	// Asia-Pacific
	"nrt": {"Tokyo", "Japan"},
	"hnd": {"Tokyo", "Japan"},
	"kix": {"Osaka", "Japan"},
	"icn": {"Seoul", "South Korea"},
	"gmp": {"Seoul", "South Korea"},
	"hkg": {"Hong Kong", "Hong Kong"},
	"sin": {"Singapore", "Singapore"},
	"kul": {"Kuala Lumpur", "Malaysia"},
	"bkk": {"Bangkok", "Thailand"},
	"cgk": {"Jakarta", "Indonesia"},
	"mnl": {"Manila", "Philippines"},
	"del": {"Delhi", "India"},
	"bom": {"Mumbai", "India"},
	"maa": {"Chennai", "India"},
	"blr": {"Bengaluru", "India"},
	"hyd": {"Hyderabad", "India"},
	"pnq": {"Pune", "India"},
	"syd": {"Sydney", "Australia"},
	"mel": {"Melbourne", "Australia"},
	"per": {"Perth", "Australia"},
	"akl": {"Auckland", "New Zealand"},
	"pvg": {"Shanghai", "China"},
	"pek": {"Beijing", "China"},

	// Latin America
	"gru": {"São Paulo", "Brazil"},
	"gig": {"Rio de Janeiro", "Brazil"},
	"eze": {"Buenos Aires", "Argentina"},
	"scl": {"Santiago", "Chile"},
	"bog": {"Bogotá", "Colombia"},
	"mex": {"Mexico City", "Mexico"},
	"qro": {"Querétaro", "Mexico"},
	"lim": {"Lima", "Peru"},

	// Middle East / Africa
	"tlv": {"Tel Aviv", "Israel"},
	"dxb": {"Dubai", "United Arab Emirates"},
	"doh": {"Doha", "Qatar"},
	"jnb": {"Johannesburg", "South Africa"},
	"cai": {"Cairo", "Egypt"},
}
