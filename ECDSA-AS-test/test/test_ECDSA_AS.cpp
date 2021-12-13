#define DEBUG

#include "../src/ECDSA_AS.hpp"

void test_ECDSA_AS()
{
    cout << "begin the basic correctness test >>>" << endl; 
    
    ECDSA_AS_PP pp; 
    ECDSA_AS_PP_new(pp); 
    ECDSA_AS_Setup(pp); 
    
    size_t TEST_NUM = 6000;

    auto start_time_dumb = chrono::steady_clock::now(); 
    BIGNUM *kk_1 = BN_new();
    BN_random(kk_1);  

    EC_POINT *KK_1 = EC_POINT_new(group);
    EC_POINT_mul(group, KK_1, kk_1, NULL, NULL, bn_ctx); // K_1 = k_1*G

    auto end_time_dumb = chrono::steady_clock::now(); 
    auto running_time_dumb = end_time_dumb - start_time_dumb;
    cout << "dumb_time = " 
    << chrono::duration <double, milli> (running_time_dumb).count() << " ms" << endl;



    ECDSA_AS_KP keypair[TEST_NUM];
    for(auto i = 0; i < TEST_NUM; i++)
    {
    ECDSA_AS_KP_new(keypair[i]);
    }

    auto start_time = chrono::steady_clock::now();

    for(auto i = 0; i < TEST_NUM; i++)
    {
    ECDSA_AS_KeyGen(pp, keypair[i]); 
    }

    auto end_time = chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    cout << "key generation takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;


    IY statwit[TEST_NUM];
    for(auto i = 0; i < TEST_NUM; i++)
    {
    IY_new(statwit[i]);
    }

    start_time = chrono::steady_clock::now();
    for(auto i = 0; i < TEST_NUM; i++)
    {
    IY_Gen(pp, statwit[i]); 
    }

    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "IY takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;


    ECDSA_AS_SIG SIG[TEST_NUM];
    for(auto i = 0; i < TEST_NUM; i++)
    { 
    ECDSA_AS_SIG_new(SIG[i]); 
    }


    string message = "hahaha";  

    start_time = chrono::steady_clock::now();
    for(auto i = 0; i < TEST_NUM; i++)
    { 
    ECDSA_AS_Sign(pp, keypair[i].sk, statwit[i].Y, message, SIG[i]);
    }
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "sign message takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;


    start_time = chrono::steady_clock::now(); 
    for(auto i = 0; i < TEST_NUM; i++)
    { 
    ECDSA_AS_Verify(pp, keypair[i].pk, statwit[i].Y, message, SIG[i]);
    }
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "verify signature takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
    }


int main()
{  
    global_initialize(NID_X9_62_prime256v1);   
    //global_initialize(NID_X25519);

    SplitLine_print('-'); 
    cout << "ECDSA_AS Signature test begins >>>>>>" << endl; 
    SplitLine_print('-'); 

    test_ECDSA_AS();

    SplitLine_print('-'); 
    cout << "ECDSA_AS Signature test finishes <<<<<<" << endl; 
    SplitLine_print('-'); 

    global_finalize();
    
    return 0; 
}



