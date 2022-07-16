#include <iostream>
#include <cstdlib>
#include <fstream>
#include <string>
#include <cmath>
#include <set>
#include <vector>
#include <unordered_map>
#include <ctime>

using namespace std;

const string PREFIX_IN_PATH = "iplookup\\finalTest\\prefix_20211122.txt";
const string TRACE_IN_PATH = "iplookup\\finalTest\\trace_20211122.txt";
const string OUT_PATH = "iplookup\\finalTest\\20211122_out.txt";

struct COMPARE {
    bool operator() (const vector<unsigned int> &lhs, const vector<unsigned int> &rhs) const{
        return (lhs[1] <= rhs[1]);   // sorted by prefix_length
    }
};

unsigned int IP_string_to_uint(string s) {
    unsigned int ip = 0;
    for (int i=3; i>=1; i--) {
        int pos = s.find('.');
        ip += (pow(256, i) * stoi(s.substr(0, pos)));
        s = s.substr(pos+1);
    }
    ip += stoi(s);
    return ip;
}

set<vector<unsigned int>, COMPARE> read_data() {
    ifstream fin(PREFIX_IN_PATH, ios::in);
    // ifstream fin("test.txt", ios::in);
    string s;
    fin >> s; fin >> s; fin >> s;       // Prefix, Next, Hop

    set<vector<unsigned int>, COMPARE> rules_sorted_by_prefix_length;
    while (fin >> s) {
        // s = Prefix, x.x.x.x/x
        int pos = s.find("/");
        vector<unsigned int> rule;
        unsigned int ip = IP_string_to_uint(s.substr(0, pos));
        unsigned int prefix_length = stoi(s.substr(pos+1));
        fin >> s;
        // s = NextHop, x.x.x.x
        rule.push_back(ip);
        rule.push_back(prefix_length);
        rule.push_back(IP_string_to_uint(s));

        rules_sorted_by_prefix_length.insert(rule);
    }

    // int count = 0;
    // for (vector<unsigned int> const &vec : rules_sorted_by_prefix_length) {
    //     cout << "IP: " << vec[0] << endl\
    //          << "Prefix_length: " << vec[1] << endl\
    //          << "Next_Hop: " << vec[2] << endl;
    //     count++;
    // }
    // cout << count << endl;

    fin.close();
    return rules_sorted_by_prefix_length;
}

const int COMPARE_ARRAY_LENGTH = 30;        // maximum 30
const int IP_LEGNTH = 32;
const unsigned int TABLE_SIZE = pow(2, COMPARE_ARRAY_LENGTH) + 5;
unsigned int *array_forwarding_table = (unsigned int *)calloc(TABLE_SIZE, sizeof(int));
unordered_map<unsigned int, unsigned int> map_forwarding_table;
unsigned int default_next_hop = 0;

void build_forwarding_table(set<vector<unsigned int>, COMPARE> &rules_sorted_by_prefix_length) {
    int count = 0;
    for (vector<unsigned int> const &vec : rules_sorted_by_prefix_length) {
        // cout << "IP: " << vec[0] << endl\
        //      << "Prefix_length: " << vec[1] << endl\
        //      << "Next_Hop: " << vec[2] << endl;

        unsigned int ip, prefix_length, nextHop, shift_prefix_legnth, shift_left_length, ip_front, ip_back;
        ip = vec[0];
        prefix_length = vec[1];
        nextHop = vec[2];

        if (prefix_length > COMPARE_ARRAY_LENGTH) {
            shift_prefix_legnth = IP_LEGNTH - prefix_length;
            ip_front = ((ip >> shift_prefix_legnth) << shift_prefix_legnth);
            ip_back = (((ip >> shift_prefix_legnth) + 1) << shift_prefix_legnth);
            // cout << "ip_front: " << ip_front << "\tip_back: " << ip_back << endl << endl;
            for (int i=ip_front; i<ip_back; i++) {
                // cout << i << endl;
                map_forwarding_table[i] = nextHop;
                count++;
            }
        }
        else {
            shift_prefix_legnth = IP_LEGNTH - prefix_length;
            shift_left_length = COMPARE_ARRAY_LENGTH - prefix_length;
            ip_front = ((ip >> shift_prefix_legnth) << shift_left_length);
            ip_back = (((ip >> shift_prefix_legnth) + 1) << shift_left_length);
            // cout << "ip_front: " << ip_front << "\tip_back: " << ip_back << endl << endl;
            for (int i=ip_front; i<ip_back; i++) {
                // cout << i << endl;
                array_forwarding_table[i] = nextHop;
            }            
        }
    }
    // cout << "count:" << count << endl;

    // for(auto it = map_forwarding_table.cbegin(); it != map_forwarding_table.cend(); ++it){
    //     std::cout << it->first << " " << it->second << "\n";
    // }
}

void trace_lookUp() {
    ifstream fin(TRACE_IN_PATH, ios::in);
    ofstream fout(OUT_PATH, ios::out);
    string s;
    fin >> s; fin >> s; fin >> s; fin >> s;     // IP, Address, Next, Hop

    time_t start_time = time(NULL), end_time;
    cout << "Start searching. Start time: " << start_time << endl;

    while (fin >> s) {
        unsigned int IP = IP_string_to_uint(s);
        fin >> s;
        unsigned int dest = IP_string_to_uint(s);
        
        if (map_forwarding_table.find(IP) == map_forwarding_table.end()) {
            // cout << "find array" << endl;
            IP = IP >> IP_LEGNTH - COMPARE_ARRAY_LENGTH;
            array_forwarding_table[IP] == dest;
            // fout << ((array_forwarding_table[IP] == dest) ? "True" : "False") << endl;
        }
        else {
            // cout << "find map" << endl;
            map_forwarding_table[IP] == dest;
            // fout << ((map_forwarding_table[IP] == dest) ? "True" : "False") << endl;
        }
    }

    end_time = time(NULL);
    cout << "end time: " << end_time << endl;
    cout << "cost: " << end_time - start_time << endl;

    fin.close();
    fout.close();
}

int main() {
    int compare_array_length = 30;
    cout << "Reading data and do some preprocessing." << endl;
    set<vector<unsigned int>, COMPARE> rules_sorted_by_prefix_length = read_data();
    cout << "Start building forwarding table." << endl;
    build_forwarding_table(rules_sorted_by_prefix_length);
    cout << "build done." << endl;
    trace_lookUp();
    return 0;
}