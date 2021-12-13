#include "../global/global.hpp"
#include "../depends/hash.hpp"
#include "../depends/print.hpp"
#include "../depends/routines.hpp"

#include <string>
#include <iostream>
#include <stdio.h>

using namespace std;

// define the structure of PP
struct SM2_AS_PP
{  
    EC_POINT *g; 
};


// define keypair 
struct SM2_AS_KP
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
struct SM2_AS_SIG
{
    BIGNUM *r; 
    BIGNUM *z;
    EC_POINT *Z;
    BIGNUM *a; 
    BIGNUM *b;
};


/* allocate memory for PP */ 
void SM2_AS_PP_new(SM2_AS_PP &pp)
{ 
    pp.g = EC_POINT_new(group);  
}


/* free memory of PP */ 
void SM2_AS_PP_free(SM2_AS_PP &pp)
{ 
    EC_POINT_free(pp.g);
}


void SM2_AS_KP_new(SM2_AS_KP &keypair)
{
    keypair.pk = EC_POINT_new(group); 
    keypair.sk = BN_new(); 
}

void SM2_AS_KP_free(SM2_AS_KP &keypair)
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

void SM2_AS_SIG_new(SM2_AS_SIG &SIG)
{
    SIG.r = BN_new(); 
    SIG.z = BN_new();
    SIG.Z = EC_POINT_new(group);
    SIG.a = BN_new(); 
    SIG.b = BN_new();
}

void SM2_AS_SIG_free(SM2_AS_SIG &SIG)
{
    BN_free(SIG.r); 
    BN_free(SIG.z);
    EC_POINT_free(SIG.Z);
    BN_free(SIG.a); 
    BN_free(SIG.b);
}


void SM2_AS_PP_print(SM2_AS_PP &pp)
{
    ECP_print(pp.g, "pp.g"); 
} 

void SM2_AS_KP_print(SM2_AS_KP &keypair)
{
    ECP_print(keypair.pk, "pk"); 
    BN_print(keypair.sk, "sk"); 
} 

void SM2_AS_SIG_print(SM2_AS_SIG &SIG)
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

void SM2_AS_SIG_serialize(SM2_AS_SIG &SIG, ofstream &fout)
{
    BN_serialize(SIG.r, fout); 
    BN_serialize(SIG.z, fout); 
} 

void SM2_AS_SIG_deserialize(SM2_AS_SIG &SIG, ifstream &fin)
{
    BN_deserialize(SIG.r, fin); 
    BN_deserialize(SIG.z, fin); 
    BN_deserialize(SIG.a, fin); 
    BN_deserialize(SIG.b, fin); 
} 


/* Setup algorithm */ 
void SM2_AS_Setup(SM2_AS_PP &pp)
{ 
    EC_POINT_copy(pp.g, generator); 

//    #ifdef DEBUG
//    cout << "generate the public parameters for SM2_AS Signature >>>" << endl; 
//    SM2_AS_PP_print(pp); 
//    #endif
}

/* KeyGen algorithm */ 
void SM2_AS_KeyGen(SM2_AS_PP &pp, SM2_AS_KP &keypair)
{ 
    BN_random(keypair.sk); // sk \sample Z_p
    EC_POINT_mul(group, keypair.pk, keypair.sk, NULL, NULL, bn_ctx); // pk = g^sk  

//    #ifdef DEBUG
//    cout << "key generation finished >>>" << endl;  
//    SM2_AS_KP_print(keypair); 
//    #endif
}

void IY_Gen(SM2_AS_PP &pp, IY &statwit)
{
    BN_random(statwit.y); // y \sample Z_p
    EC_POINT_mul(group, statwit.Y, statwit.y, NULL, NULL, bn_ctx); // Y = yG
}

/* This function takes as input a message, returns a signature. */
void SM2_AS_Sign(SM2_AS_PP &pp, EC_POINT *&pk, BIGNUM *&sk, EC_POINT *&Y, string &message, SM2_AS_SIG &SIG)
{
    SM2_AS_SIG sig; // define the signature
    BIGNUM *k = BN_new();
    BN_random(k);  

    EC_POINT *K1 = EC_POINT_new(group);

    EC_POINT_mul(group, K1, k, NULL, NULL, bn_ctx); // K1=kG


    //EC_POINT *K2 = EC_POINT_new(group);
    BIGNUM *aa = BN_new();
    BN_set_word(aa, 1);//aa=1
    // char   *p_r_x1aa;
    // p_r_x1aa=BN_bn2hex(aa);
    // cout << "p_r_x1aa >>>"<< p_r_x1aa << endl;


    BIGNUM *sk_1 = BN_new();
    BN_mod_add(sk_1,aa,sk,order,bn_ctx);//sk_1=1+sk=1+x
    // cout << "sk_1 >>>"<< sk_1 << endl;
    // char   *p_r_x1sk1;
    // p_r_x1sk1=BN_bn2hex(sk_1);
    // cout << "p_r_x1sk1 >>>"<< p_r_x1sk1 << endl;

    EC_POINT_mul(group, SIG.Z, NULL, Y, sk_1, bn_ctx); // SIG.Z=(sk+1)Y=(x+1)Y
    
    EC_POINT *K1_Z = EC_POINT_new(group);
    EC_POINT_add(group, K1_Z, K1, SIG.Z, bn_ctx);        // K1_Z = K1+SIG.Z=kG+(x+1)Y

    BIGNUM *r_x = BN_new();
    BIGNUM *r_y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, K1_Z, r_x, r_y, bn_ctx);//r_x

    //(x+1)^{-1}(k-sk*r_x)
    // compute e = H(m)
    BIGNUM *e = BN_new();
    Hash_String_to_BN(message, e);//e=H(m)

    BN_mod_add(SIG.r, e, r_x, order, bn_ctx); //SIG.r=r_x+e
    BIGNUM *SIG_r_sk = BN_new();
    BN_mod_mul(SIG_r_sk, SIG.r, sk, order, bn_ctx); // SIG_r_sk=SIG.r*sk=rx; 
    BIGNUM *k_SIG_r_sk = BN_new();
    BN_mod_sub(k_SIG_r_sk, k, SIG_r_sk, order, bn_ctx); //k_SIG_r_sk=k-rx
    BIGNUM *inv_sk_1 = BN_new();
    BN_mod_inverse(inv_sk_1, sk_1, order, bn_ctx);//inv-sk_1=(1+x)^{-1}
    BN_mod_mul(SIG.z, inv_sk_1, k_SIG_r_sk, order, bn_ctx); //z=(1+x)^{-1}(k-rx) mod n


    //prove((G,X,Y,SIG.Z),x)->\pi=(SIG.a,SIG.b)
    BIGNUM *kk = BN_new();
    BN_random(kk);  

    EC_POINT *KK1 = EC_POINT_new(group);
    EC_POINT_mul(group, KK1, kk, NULL, NULL, bn_ctx); // KK1=kkG   

    EC_POINT *KK2 = EC_POINT_new(group);
    EC_POINT_mul(group, KK2, NULL, Y, kk, bn_ctx); // KK2=kkY

    BIGNUM *r_x1 = BN_new();
    BIGNUM *r_y1 = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, SIG.Z, r_x1, r_y1, bn_ctx);//r_x1=f(Z)

    BIGNUM *r_x2 = BN_new();
    BIGNUM *r_y2 = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, pk, r_x2, r_y2, bn_ctx);//r_x2=f(pk=X)

    BIGNUM *r_xx1 = BN_new();
    BIGNUM *r_yy1 = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, KK1, r_xx1, r_yy1, bn_ctx);//r_xx1=f(KK1)=f(kkG)

    BIGNUM *r_xx2 = BN_new();
    BIGNUM *r_yy2 = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, KK2, r_xx2, r_yy2, bn_ctx);//r_xx2=f(KK2)=f(kkY)

    //x=Hash(K1,K2,KK1,KK2)=Hash(Z=(x+1)Y,X=xG,kkG,kkY), b=kk+x*k
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
    p_r_x2=BN_bn2hex(r_x2);
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

    s_r_y2=p_r_y2;

    s_r_xx1=p_r_xx1;

    s_r_yy1=p_r_yy1;

    s_r_xx2=p_r_xx2;

    s_r_yy2=p_r_yy2;


    s_r_x1=s_r_x1+s_r_y1;
    s_r_x1=s_r_x1+s_r_x2;
    s_r_x1=s_r_x1+s_r_y2;
    s_r_x1=s_r_x1+s_r_xx1;
    s_r_x1=s_r_x1+s_r_yy1;
    s_r_x1=s_r_x1+s_r_xx2;
    s_r_x1=s_r_x1+s_r_yy2;

    Hash_String_to_BN(s_r_x1, SIG.a);//SIG.a=Hash(K1,K2,KK1,KK2)
    //cout << "s_r_x1 >>>"<< s_r_x1 << endl;

    BIGNUM *sk_a = BN_new();
    BN_mod_mul(sk_a, sk, SIG.a, order, bn_ctx); // sk_a = sk*a=a*x; 

    BN_mod_add(SIG.b,kk,sk_a,order,bn_ctx);//SIG.b=kk+sk*a=kk+sk*a

//    #ifdef DEBUG
//        cout << "SM2_AS signature generation finishes >>>" << endl;
//        SM2_AS_SIG_print(SIG);  
//    #endif


}


/* This function verifies the signature is valid for the message "msg_file" */

bool SM2_AS_Verify(SM2_AS_PP &pp, EC_POINT *&pk, EC_POINT *&Y, string &message, SM2_AS_SIG &SIG)
{
    bool Validity;       

    // compute e = H(A||m)
    BIGNUM *e = BN_new(); 
    Hash_String_to_BN(message, e);//e=h(m)
    
    BIGNUM *SIG_z_r = BN_new();
    BN_mod_add(SIG_z_r,SIG.z,SIG.r,order,bn_ctx);//SIG_z_r=SIG.z+SIG.r=z+r 

    EC_POINT *LEFT = EC_POINT_new(group);
    EC_POINT *RIGHT = EC_POINT_new(group);

    EC_POINT_mul(group, LEFT, SIG.z, NULL, NULL, bn_ctx); // LEFT = z*G 
    EC_POINT_mul(group, RIGHT, NULL, pk, SIG_z_r, bn_ctx);   // RIGHT = (z+r)*pk
    EC_POINT_add(group, RIGHT, RIGHT, LEFT, bn_ctx);        // RIGHT = RIGHT+LEFT=(z+r)X+zG
    EC_POINT_add(group, RIGHT, RIGHT, SIG.Z, bn_ctx);        // RIGHT = RIGHT+Z=(z+r)X+zG+Z
//RIGHT=kG+Z=kG+(x+1)Y
  
//    EC_POINT_get_affine_coordinates_GFp(group, RIGHT, rrr_x, rrr_y, bn_ctx);
//    BN_print(rrr_x, "rrr_x");
//    BN_print(rrr_y, "rrr_y");

    
    EC_POINT *SIG_b_G = EC_POINT_new(group);
    EC_POINT *G_a = EC_POINT_new(group);
    EC_POINT *inv_G_a = EC_POINT_new(group);
    EC_POINT *V_KK1 = EC_POINT_new(group);

    EC_POINT *SIG_b_Y = EC_POINT_new(group);
    EC_POINT *Z_a = EC_POINT_new(group);
    EC_POINT *inv_Z_a = EC_POINT_new(group);
    EC_POINT *V_KK2 = EC_POINT_new(group);

// V_KK1=kkG, (kk+sk*a)G-a*(skG)
    EC_POINT_mul(group, SIG_b_G, SIG.b, NULL, NULL, bn_ctx); // SIG_b_Y = (b)*G=(kk+x*a)G
    EC_POINT_mul(group, G_a, NULL, pk, SIG.a, bn_ctx); // G_a = a*pk=axG   
    EC_POINT_copy(inv_G_a, G_a);//invSIG_a_G=SIG_a_G
    EC_POINT_invert(group, inv_G_a, bn_ctx);//inv_Z_a=-inv_Z_a
    EC_POINT_add(group, V_KK1, SIG_b_G, inv_G_a, bn_ctx);        // V_KK1 = SIG_b_G-inv_G_a=(kk+a(x))G-a(x)G =kkY

// V_KK2=kkY   
    BIGNUM *b_a = BN_new();
    BN_mod_add(b_a,SIG.b,SIG.a,order,bn_ctx);//b_a=b+a

    EC_POINT_mul(group, SIG_b_Y, NULL, Y, b_a, bn_ctx); // SIG_b_Y = (b+a)*Y=(kk+x*a+a)Y=kkY+a(x+1)Y 
    EC_POINT_mul(group, Z_a, NULL, SIG.Z, SIG.a, bn_ctx); // Z_a = a*Z=a(x+1)Y     
    EC_POINT_copy(inv_Z_a, Z_a);//invSIG_a_G=SIG_a_G
    EC_POINT_invert(group, inv_Z_a, bn_ctx);//inv_Z_a=-inv_Z_a
    EC_POINT_add(group, V_KK2, SIG_b_Y, inv_Z_a, bn_ctx);        // V_KK2 = SIG_b_Y-inv_Z_a=kkY+a(x+1)Y-a(x+1)Y =kkY


    //x=Hash(K1,K2,KK1,KK2)=Hash(Z=(x+1)Y,X=xG,kkG,kkY), b=kk+x*k
    BIGNUM *r_a1 = BN_new();
    BIGNUM *r_b1 = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, SIG.Z, r_a1, r_b1, bn_ctx);

    BIGNUM *r_a2 = BN_new();
    BIGNUM *r_b2 = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, pk, r_a2, r_b2, bn_ctx);


    BIGNUM *r_aa1 = BN_new();
    BIGNUM *r_bb1 = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, V_KK1, r_aa1, r_bb1, bn_ctx);

    BIGNUM *r_aa2 = BN_new();
    BIGNUM *r_bb2 = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, V_KK2, r_aa2, r_bb2, bn_ctx);


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
//    cout << "s_r_a1 >>>"<< s_r_a1 << endl;

    s_r_b2=p_r_b2;

    s_r_aa1=p_r_aa1;
//    cout << "s_r_aa1 >>>"<< s_r_aa1 << endl;


    s_r_bb1=p_r_bb1;
//    cout << "s_r_bb1 >>>"<< s_r_bb1 << endl;

    s_r_aa2=p_r_aa2;
//    cout << "s_r_aa1 >>>"<< s_r_aa1 << endl;


    s_r_bb2=p_r_bb2;


    s_r_a1=s_r_a1+s_r_b1;
    s_r_a1=s_r_a1+s_r_a2;
    s_r_a1=s_r_a1+s_r_b2;
    s_r_a1=s_r_a1+s_r_aa1;
    s_r_a1=s_r_a1+s_r_bb1;
    s_r_a1=s_r_a1+s_r_aa2;
    s_r_a1=s_r_a1+s_r_bb2;

    BIGNUM *temp_SIG_a = BN_new();
    Hash_String_to_BN(s_r_a1, temp_SIG_a);//SIG.a=Hash(Z,KK1)
    //cout << "s_r_a1 >>>"<< s_r_a1 << endl;

    //cout << "temp_SIG_a >>>"<< temp_SIG_a << endl;

    //cout << "SIG_a >>>"<< SIG.a << endl;

//check f(K2)=f(SIG.Z)=r=f(kY)?
    BIGNUM *rrr_x = BN_new();
    BIGNUM *rrr_y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, RIGHT, rrr_x, rrr_y, bn_ctx);
    BIGNUM *rrr_x_m = BN_new();
    BN_mod_add(rrr_x_m,rrr_x,e,order,bn_ctx);//rrr_x_m=rrr_x+m


    if(BN_cmp(temp_SIG_a,SIG.a)==0 && BN_cmp(rrr_x_m,SIG.r)==0){
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
    EC_POINT_free(LEFT);
    EC_POINT_free(RIGHT);  

    return Validity;
}