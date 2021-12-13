#include "../global/global.hpp"
#include "../depends/hash.hpp"
#include "../depends/print.hpp"
#include "../depends/routines.hpp"

#include <string>
#include <iostream>
#include <stdio.h>

using namespace std;

// define the structure of PP
struct ECDSA_AS_PP
{  
    EC_POINT *g; 
};


// define keypair 
struct ECDSA_AS_KP
{
    EC_POINT *pk; // define pk
    BIGNUM *sk;   // define sk
};

struct IY
{
    EC_POINT *Y; // define point Y
    BIGNUM *y;   // define bignum y
};

// define signature 
struct ECDSA_AS_SIG
{
    BIGNUM *r; 
    BIGNUM *z;
    EC_POINT *Z;
    BIGNUM *a; 
    BIGNUM *b;
};


/* allocate memory for PP */ 
void ECDSA_AS_PP_new(ECDSA_AS_PP &pp)
{ 
    pp.g = EC_POINT_new(group);  
}


/* free memory of PP */ 
void ECDSA_AS_PP_free(ECDSA_AS_PP &pp)
{ 
    EC_POINT_free(pp.g);
}


void ECDSA_AS_KP_new(ECDSA_AS_KP &keypair)
{
    keypair.pk = EC_POINT_new(group); 
    keypair.sk = BN_new(); 
}

void ECDSA_AS_KP_free(ECDSA_AS_KP &keypair)
{
    EC_POINT_free(keypair.pk); 
    BN_free(keypair.sk);
}

void IY_free(IY &statwit)
{
    EC_POINT_free(statwit.Y); 
    BN_free(statwit.y);
}

void IY_new(IY &statwit)
{
    statwit.Y=EC_POINT_new(group); 
    statwit.y=BN_new();
}

void ECDSA_AS_SIG_new(ECDSA_AS_SIG &SIG)
{
    SIG.r = BN_new(); 
    SIG.z = BN_new();
    SIG.Z = EC_POINT_new(group);
    SIG.a = BN_new(); 
    SIG.b = BN_new();
}

void ECDSA_AS_SIG_free(ECDSA_AS_SIG &SIG)
{
    BN_free(SIG.r); 
    BN_free(SIG.z);
    EC_POINT_free(SIG.Z);
    BN_free(SIG.a); 
    BN_free(SIG.b);
}


void ECDSA_AS_PP_print(ECDSA_AS_PP &pp)
{
    ECP_print(pp.g, "pp.g"); 
} 

void ECDSA_AS_KP_print(ECDSA_AS_KP &keypair)
{
    ECP_print(keypair.pk, "pk"); 
    BN_print(keypair.sk, "sk"); 
} 

void ECDSA_AS_SIG_print(ECDSA_AS_SIG &SIG)
{
    BN_print(SIG.r, "SIG.r");
    BN_print(SIG.z, "SIG.z");
    ECP_print(SIG.Z, "SIG.Z"); 
    BN_print(SIG.a, "SIG.a");
    BN_print(SIG.b, "SIG.b");
} 

void IY_print(IY &statwit)
{
    ECP_print(statwit.Y, "Y"); 
    BN_print(statwit.y, "y");
}

void ECDSA_AS_SIG_serialize(ECDSA_AS_SIG &SIG, ofstream &fout)
{
    BN_serialize(SIG.r, fout); 
    BN_serialize(SIG.z, fout); 
} 

void ECDSA_AS_SIG_deserialize(ECDSA_AS_SIG &SIG, ifstream &fin)
{
    BN_deserialize(SIG.r, fin); 
    BN_deserialize(SIG.z, fin); 
    BN_deserialize(SIG.a, fin); 
    BN_deserialize(SIG.b, fin); 
} 


/* Setup algorithm */ 
void ECDSA_AS_Setup(ECDSA_AS_PP &pp)
{ 
    EC_POINT_copy(pp.g, generator); 

//    #ifdef DEBUG
//    cout << "generate the public parameters for ECDSA_AS Signature >>>" << endl; 
//    ECDSA_AS_PP_print(pp); 
//    #endif
}

/* KeyGen algorithm */ 
void ECDSA_AS_KeyGen(ECDSA_AS_PP &pp, ECDSA_AS_KP &keypair)
{ 
    BN_random(keypair.sk); // sk \sample Z_p
    EC_POINT_mul(group, keypair.pk, keypair.sk, NULL, NULL, bn_ctx); // pk = g^sk  

//    #ifdef DEBUG
//    cout << "key generation finished >>>" << endl;  
//    ECDSA_AS_KP_print(keypair); 
//    #endif
}

void IY_Gen(ECDSA_AS_PP &pp, IY &statwit)
{
    BN_random(statwit.y); // y \sample Z_p
    EC_POINT_mul(group, statwit.Y, statwit.y, NULL, NULL, bn_ctx); // Y = yG
}

/* This function takes as input a message, returns a signature. */
void ECDSA_AS_Sign(ECDSA_AS_PP &pp, BIGNUM *&sk, EC_POINT *&Y, string &message, ECDSA_AS_SIG &SIG)
{
    ECDSA_AS_SIG sig; // define the signature
    BIGNUM *k = BN_new();
    BN_random(k);  

    EC_POINT *K1 = EC_POINT_new(group);

    EC_POINT_mul(group, K1, k, NULL, NULL, bn_ctx); // K1=kG


    //EC_POINT *K2 = EC_POINT_new(group);

    EC_POINT_mul(group, SIG.Z, NULL, Y, k, bn_ctx); // SIG.Z=kY

    BIGNUM *r_x1 = BN_new();
    BIGNUM *r_y1 = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, K1, r_x1, r_y1, bn_ctx);//SIG.r=r_x=f(K1)=f(kG)

    BIGNUM *r_y2 = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, SIG.Z, SIG.r, r_y2, bn_ctx);//r_x

    //k^{-1}(e+sk*r_x)
    // compute e = H(m)
    BIGNUM *e = BN_new();
    Hash_String_to_BN(message, e);//e=H(m)

    BIGNUM *temp_sk = BN_new();
    BN_mul(temp_sk, sk, SIG.r, bn_ctx); //temp_sk=sk*r_x

    //k^{-1}
    BIGNUM *temp_r = BN_new();
    BN_mod_inverse(temp_r, k, order, bn_ctx);//temp_r=k^{-1}

    BIGNUM *temp_z = BN_new();
    BN_mod_add(temp_z,e,temp_sk,order,bn_ctx);//temp_z=e+sk*r_x

    BN_mod_mul(SIG.z, temp_z, temp_r, order, bn_ctx); // z = temp_r*temp_z=k^{-1}(e+sk*r_x); 

    //prove((K1,SIG.Z),k)->\pi=(a,b)
    BIGNUM *kk = BN_new();
    BN_random(kk);  

    EC_POINT *KK1 = EC_POINT_new(group);

    EC_POINT_mul(group, KK1, kk, NULL, NULL, bn_ctx); // KK1=kkG


    EC_POINT *KK2 = EC_POINT_new(group);

    EC_POINT_mul(group, KK2, NULL, Y, kk, bn_ctx); // KK2=kkY

    BIGNUM *r_xx1 = BN_new();
    BIGNUM *r_yy1 = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, KK1, r_xx1, r_yy1, bn_ctx);//r_xx1=f(K1)=f(kG)

    BIGNUM *r_xx2 = BN_new();
    BIGNUM *r_yy2 = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, KK2, r_xx2, r_yy2, bn_ctx);

    //x=Hash(K1,K2,KK1,KK2), b=kk+x*k
    //K1||K2||KK1||KK2
    //char   *p_r_x1=NULL;

    char   *p_r_x1;
    char   *p_r_y1;
    char   *p_r_x2;
    char   *p_r_y2;
    char   *p_r_xx1;
    char   *p_r_yy1;
    char   *p_r_xx2;
    char   *p_r_yy2;

    string   s_r_x1;
    string   s_r_y1;
    string   s_r_x2;
    string   s_r_y2;
    string   s_r_xx1;
    string   s_r_yy1;
    string   s_r_xx2;
    string   s_r_yy2;

    p_r_x1=BN_bn2hex(r_x1);
    p_r_y1=BN_bn2hex(r_y1);
    p_r_x2=BN_bn2hex(SIG.r);
    p_r_y2=BN_bn2hex(r_y2);
    p_r_xx1=BN_bn2hex(r_xx1);
    p_r_yy1=BN_bn2hex(r_yy1);
    p_r_xx2=BN_bn2hex(r_xx2);
    p_r_yy2=BN_bn2hex(r_yy2);

    s_r_x1=p_r_x1;
//    cout << "s_r_x1 >>>"<< s_r_x1 << endl;

    s_r_y1=p_r_y1;
//    cout << "s_r_y1 >>>"<< s_r_y1 << endl;

    s_r_x2=p_r_x2;
//    cout << "s_r_x2 >>>"<< s_r_x2 << endl;

    s_r_y2=p_r_y2;
//    cout << "s_r_y2 >>>"<< s_r_y2 << endl;


    s_r_xx1=p_r_xx1;
//    cout << "s_r_xx1 >>>"<< s_r_xx1 << endl;


    s_r_yy1=p_r_yy1;
//    cout << "s_r_yy1 >>>"<< s_r_yy1 << endl;


    s_r_xx2=p_r_xx2;
//    cout << "s_r_xx2 >>>"<< s_r_xx2 << endl;


    s_r_yy2=p_r_yy2;
//    cout << "s_r_yy2 >>>"<< s_r_yy2 << endl;

    s_r_x1=s_r_x1+s_r_y1;
    s_r_x1=s_r_x1+s_r_x2;
    s_r_x1=s_r_x1+s_r_y2;
    s_r_x1=s_r_x1+s_r_xx1;
    s_r_x1=s_r_x1+s_r_yy1;
    s_r_x1=s_r_x1+s_r_xx2;
    s_r_x1=s_r_x1+s_r_yy2;

    Hash_String_to_BN(s_r_x1, SIG.a);//SIG.a=Hash(K1,K2,KK1,KK2)
    //cout << "s_r_x1 >>>"<< s_r_x1 << endl;

    BIGNUM *temp_a = BN_new();
    BN_mod_mul(temp_a, k, SIG.a, order, bn_ctx); // temp_a = k*a; 

    BN_mod_add(SIG.b,kk,temp_a,order,bn_ctx);//SIG.b=kk+temp_a=kk+k*a

//    #ifdef DEBUG
//        cout << "ECDSA_AS signature generation finishes >>>" << endl;
//        ECDSA_AS_SIG_print(SIG);  
//    #endif

    BN_free(k); 
    EC_POINT_free(KK1);
    EC_POINT_free(KK2);
    BN_free(e); 
    BN_free(temp_sk);
    BN_free(temp_r);
    BN_free(temp_z);
    BN_free(temp_a);
}


bool ECDSA_AS_Verify(ECDSA_AS_PP &pp, EC_POINT *&pk, EC_POINT *&Y, string &message, ECDSA_AS_SIG &SIG)
{
    bool Validity;       

    // compute e = H(A||m)
    BIGNUM *e = BN_new(); 
    Hash_String_to_BN(message, e);//e=h(m)
    
    BIGNUM *temp_z = BN_new();
    BN_mod_inverse(temp_z, SIG.z, order, bn_ctx);//temp_z=z^{-1}
    
    BIGNUM *temp_m = BN_new();
    BN_mod_mul(temp_m, temp_z, e, order, bn_ctx); // m = z^{-1}*e; 

    BIGNUM *temp_r_x = BN_new();
    BN_mod_mul(temp_r_x, temp_z, SIG.r, order, bn_ctx); // z^{-1}*r_x; 


    EC_POINT *LEFT = EC_POINT_new(group);
    EC_POINT *RIGHT = EC_POINT_new(group);

    EC_POINT_mul(group, LEFT, temp_m, NULL, NULL, bn_ctx); // LEFT = m*G 
    EC_POINT_mul(group, RIGHT, NULL, pk, temp_r_x, bn_ctx);   // RIGHT = r_x*pk
    EC_POINT_add(group, RIGHT, RIGHT, LEFT, bn_ctx);        // RIGHT = RIGHT+LEFT=kG=K1
   
//    EC_POINT_get_affine_coordinates_GFp(group, RIGHT, rrr_x, rrr_y, bn_ctx);
//    BN_print(rrr_x, "rrr_x");
//    BN_print(rrr_y, "rrr_y");

    EC_POINT *SIG_b_G = EC_POINT_new(group);
    EC_POINT *invSIG_a_G = EC_POINT_new(group);
    EC_POINT *SIG_a_G = EC_POINT_new(group);
    EC_POINT *V_KK1 = EC_POINT_new(group);
    EC_POINT *SIG_b_Y = EC_POINT_new(group);
    EC_POINT *SIG_a_Y = EC_POINT_new(group);
    EC_POINT *invSIG_a_Y = EC_POINT_new(group);
    EC_POINT *V_KK2 = EC_POINT_new(group);

// V_KK1
    EC_POINT_mul(group, SIG_b_G, SIG.b, NULL, NULL, bn_ctx); // SIG_b_G = SIG.b*G=(kk+k*a)G 
    EC_POINT_mul(group, SIG_a_G, NULL, RIGHT, SIG.a, bn_ctx);   // SIG_a_G = SIG.a*RIGHT=a*K1
    EC_POINT_copy(invSIG_a_G, SIG_a_G);//invSIG_a_G=SIG_a_G
    EC_POINT_invert(group, invSIG_a_G, bn_ctx);//invSIG_a_G=-SIG_a_G
    EC_POINT_add(group, V_KK1, SIG_b_G, invSIG_a_G, bn_ctx);        // V_KK1 = SIG_b_G+invSIG_a_G=(kk+k*a)G-aK1=kkG=KK1
// V_KK2
    EC_POINT_mul(group, SIG_b_Y, NULL, Y, SIG.b, bn_ctx); // SIG_b_Y = SIG.b*Y=(kk+k*a)G 
    EC_POINT_mul(group, SIG_a_Y, NULL, SIG.Z, SIG.a, bn_ctx);   // SIG_a_G = SIG.a*RIGHT=a*K1
    EC_POINT_copy(invSIG_a_Y, SIG_a_Y);//invSIG_a_G=SIG_a_G
    EC_POINT_invert(group, invSIG_a_Y, bn_ctx);//invSIG_a_G=-SIG_a_G
    EC_POINT_add(group, V_KK2, SIG_b_Y, invSIG_a_Y, bn_ctx);        // V_KK1 = SIG_b_G+invSIG_a_G=(kk+k*a)G-aK1=kkG=KK1

//compute Hash(K1||K2||KK1||KK2)=Hash(RIGHT||SIG.Z||V_KK1||V_KK2)
    BIGNUM *r_a1 = BN_new();
    BIGNUM *r_b1 = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, RIGHT, r_a1, r_b1, bn_ctx);//r_xx1=f(K1)=f(kG)

    BIGNUM *r_a2 = BN_new();
    BIGNUM *r_b2 = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, SIG.Z, r_a2, r_b2, bn_ctx);//r_xx1=f(K1)=f(kG)

    BIGNUM *r_aa1 = BN_new();
    BIGNUM *r_bb1 = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, V_KK1, r_aa1, r_bb1, bn_ctx);//r_xx1=f(K1)=f(kG)


    BIGNUM *r_aa2 = BN_new();
    BIGNUM *r_bb2 = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, V_KK2, r_aa2, r_bb2, bn_ctx);//r_xx1=f(K1)=f(kG)


    char   *p_r_a1;
    char   *p_r_b1;
    char   *p_r_a2;
    char   *p_r_b2;
    char   *p_r_aa1;
    char   *p_r_bb1;
    char   *p_r_aa2;
    char   *p_r_bb2;

    string   s_r_a1;
    string   s_r_b1;
    string   s_r_a2;
    string   s_r_b2;
    string   s_r_aa1;
    string   s_r_bb1;
    string   s_r_aa2;
    string   s_r_bb2;

    p_r_a1=BN_bn2hex(r_a1);
    p_r_b1=BN_bn2hex(r_b1);
    p_r_a2=BN_bn2hex(r_a2);
    p_r_b2=BN_bn2hex(r_b2);
    p_r_aa1=BN_bn2hex(r_aa1);
    p_r_bb1=BN_bn2hex(r_bb1);
    p_r_aa2=BN_bn2hex(r_aa2);
    p_r_bb2=BN_bn2hex(r_bb2);

    s_r_a1=p_r_a1;
//    cout << "s_r_a1 >>>"<< s_r_a1 << endl;

    s_r_b1=p_r_b1;
//    cout << "s_r_b1 >>>"<< s_r_b1 << endl;

    s_r_a2=p_r_a2;
//    cout << "s_r_a2 >>>"<< s_r_a2 << endl;

    s_r_b2=p_r_b2;
//    cout << "s_r_b2 >>>"<< s_r_b2 << endl;


    s_r_aa1=p_r_aa1;
//    cout << "s_r_aa1 >>>"<< s_r_aa1 << endl;


    s_r_bb1=p_r_bb1;
//    cout << "s_r_bb1 >>>"<< s_r_bb1 << endl;


    s_r_aa2=p_r_aa2;
//    cout << "s_r_aa2 >>>"<< s_r_aa2 << endl;


    s_r_bb2=p_r_bb2;
//    cout << "s_r_bb2 >>>"<< s_r_bb2 << endl;



    s_r_a1=s_r_a1+s_r_b1;
    s_r_a1=s_r_a1+s_r_a2;
    s_r_a1=s_r_a1+s_r_b2;
    s_r_a1=s_r_a1+s_r_aa1;
    s_r_a1=s_r_a1+s_r_bb1;
    s_r_a1=s_r_a1+s_r_aa2;
    s_r_a1=s_r_a1+s_r_bb2;

    BIGNUM *temp_SIG_a = BN_new();
    Hash_String_to_BN(s_r_a1, temp_SIG_a);//SIG.a=Hash(K1,K2,KK1,KK2)
    //cout << "s_r_a1 >>>"<< s_r_a1 << endl;

    //cout << "temp_SIG_a >>>"<< temp_SIG_a << endl;

    //cout << "SIG_a >>>"<< SIG.a << endl;

    //check f(K2)=f(SIG.Z)=r=f(kY)?
    BIGNUM *rrr_x = BN_new();
    BIGNUM *rrr_y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, SIG.Z, rrr_x, rrr_y, bn_ctx);


    if(BN_cmp(rrr_x,SIG.r)==0 && BN_cmp(temp_SIG_a,SIG.a)==0){
        Validity = true; 
    }
    else Validity = false; 
 
   // #ifdef DEBUG
   // if (Validity)
   // {
   //     cout << "Signature is Valid >>>" << endl;
   // }
   // else
   // {
   //     cout << "Signature is Invalid >>>" << endl;
   // }
   // #endif


    BN_free(e); 
    BN_free(rrr_x);
    BN_free(rrr_y);
    BN_free(temp_z); 
    BN_free(temp_m);
    BN_free(temp_r_x);
    EC_POINT_free(LEFT);
    EC_POINT_free(RIGHT);  

    return Validity;
}