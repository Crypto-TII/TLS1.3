// Utility to, for example, convert a Linux ca-certificates.crt file to a form suitable for inclusion in the C++ and Rust code
// Input: file.crt
// Output: file.cpp (for inclusion in cpp/lib/tls_cacerts.cpp)
//         file.rs (for inclusion in rust/client/src/tls13/cacerts.rs and rust/server/src/tls13/cacerts.rs)
//
// g++ -O2 convert.cpp -o convert

#include <iostream>
#include <fstream>
#include <string.h>

using namespace std;

int main(int argc,char **argv)
{
    argv++; argc--;
    if (argc!=1)
    {
        cout << "Incorrect Usage" << endl;
        cout << "convert file.crt" << endl;
        cout << "Outputs file.cpp and file.rs" << endl;
        return 0;
    }
    string filename=argv[0];
    ifstream cacerts(filename.c_str()); 
    string file=filename.substr(0,filename.find('.'));
    string filecpp=file+".cpp";
    string filers=file+".rs";
    ofstream cpp(filecpp.c_str());
    ofstream rust(filers.c_str());
    string line;
    string start="-----BEGIN CERTIFICATE-----";
    string end="-----END CERTIFICATE-----";

// C++
    while (getline(cacerts,line)) {
        cpp << "\"" << line << "\\n\"" << endl;
    }
    cpp << ";" << endl;

    cacerts.close();
    cacerts.open(filename.c_str());

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
