// Need to keep ticket, nonce, rms
// should add time stamp
/*
    ofstream resumption("resume.sta");

    resumption << TICK.len << endl;
    for (int i=0;i<TICK.len;i++)
        resumption << (unsigned int)(unsigned char)TICK.val[i] << endl;
    resumption << NONCE.len << endl;
    for (int i=0;i<NONCE.len;i++)
        resumption << (unsigned int)(unsigned char)NONCE.val[i] << endl;
    resumption << RMS.len << endl;
    for (int i=0;i<RMS.len;i++)
        resumption << (unsigned int)(unsigned char)RMS.val[i] << endl;

    printf("Stored Ticket= ");OCT_output(&TICK);

    resumption.close();
    return 0;
}


    ifstream back("resume.sta");

    unsigned int fred;
    back >> TICK.len;
    for (int i=0;i<TICK.len;i++)
    {
        back >> fred;
        TICK.val[i]=fred;
    }
    back >> NONCE.len;
    for (int i=0;i<NONCE.len;i++)
    {
        back >> fred;
        NONCE.val[i] = fred;
    }
    back >> RMS.len;
    for (int i=0;i<RMS.len;i++)
    {
        back >> fred;
        RMS.val[i]=fred;
    }

*/

