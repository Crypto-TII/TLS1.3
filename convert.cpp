// Utility to convert a Linux ca-certificates.crt file to a form suitable for inclusion in the C++ and Rust code
// Input: ca-certificates.crt
// Output: ca-certificates.cpp (for inclusion in cpp/lib/tls_cacerts.cpp)
//         ca-certificates.rs (for inclusion in rust/client/src/cacerts.rs and rust/server/src/cacerts.rs)
//
// g++ -O2 convert.cpp -o convert

#include <iostream>
#include <fstream>
#include <string.h>

using namespace std;

int main()
{
    ifstream cacerts("ca-certificates.crt"); 
    ofstream cpp("ca-certificates.cpp");
    ofstream rust("ca-certificates.rs");
    string line;
    string start="-----BEGIN CERTIFICATE-----";
    string end="-----END CERTIFICATE-----";

// C++
    while (getline(cacerts,line)) {
        cpp << "\"" << line << "\\n\"" << endl;
    }
    cpp << ";" << endl;

    cacerts.close();
    cacerts.open("ca-certificates.crt");

// Rust
    bool finished=true;
    int ncerts=0;
    while (getline(cacerts,line)) {
        if (line.compare(start)==0) {
            rust << "\"";
            finished=false;
            continue;
        }
        if (line.compare(end)==0)
        {
            if (!finished)
            {
                finished=true;
                rust << "\"," << endl;
            }
            ncerts++;
            continue;
        }
        if (line.length()==64)
            rust << line << "\\" << endl;
        else {
            finished=true;
            rust << line << "\"," << endl;
        }
    }
    cout << "Number of Certs= " << ncerts << endl;
    return 0;
}
