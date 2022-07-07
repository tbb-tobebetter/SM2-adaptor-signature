#include "../global/global.hpp"
#include "../depends/hash.hpp"
#include "../depends/print.hpp"
#include "../depends/routines.hpp"

#include <string>
#include <iostream>
#include <stdio.h>

using namespace std;

// define the structure of PP
struct SM2_AS_our_PP
{  
    EC_POINT *g; 
};


// define keypair 
struct SM2_AS_our_KP
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
struct SM2_AS_our_SIG
{
    BIGNUM *r; 
    BIGNUM *z;
};


/* allocate memory for PP */ 
void SM2_AS_our_PP_new(SM2_AS_our_PP &pp)
{ 
    pp.g = EC_POINT_new(group);  
}


/* free memory of PP */ 
void SM2_AS_our_PP_free(SM2_AS_our_PP &pp)
{ 
    EC_POINT_free(pp.g);
}


void SM2_AS_our_KP_new(SM2_AS_our_KP &keypair)
{
    keypair.pk = EC_POINT_new(group); 
    keypair.sk = BN_new(); 
}

void SM2_AS_our_KP_free(SM2_AS_our_KP &keypair)
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

void SM2_AS_our_SIG_new(SM2_AS_our_SIG &SIG)
{
    SIG.r = BN_new(); 
    SIG.z = BN_new();
}

void SM2_AS_our_SIG_free(SM2_AS_our_SIG &SIG)
{
    BN_free(SIG.r); 
    BN_free(SIG.z);
}


void SM2_AS_our_PP_print(SM2_AS_our_PP &pp)
{
    ECP_print(pp.g, "pp.g"); 
} 

void SM2_AS_our_KP_print(SM2_AS_our_KP &keypair)
{
    ECP_print(keypair.pk, "pk"); 
    BN_print(keypair.sk, "sk"); 
} 

void SM2_AS_our_SIG_print(SM2_AS_our_SIG &SIG)
{
    BN_print(SIG.r, "SIG.r");
    BN_print(SIG.z, "SIG.z");
} 

void IY_print(IY &statwit)
{
    ECP_print(statwit.Y, "Y"); 
    BN_print(statwit.y, "y");
}

void SM2_AS_our_SIG_serialize(SM2_AS_our_SIG &SIG, ofstream &fout)
{
    BN_serialize(SIG.r, fout); 
    BN_serialize(SIG.z, fout); 
} 

void SM2_AS_our_SIG_deserialize(SM2_AS_our_SIG &SIG, ifstream &fin)
{
    BN_deserialize(SIG.r, fin); 
    BN_deserialize(SIG.z, fin); 
} 


/* Setup algorithm */ 
void SM2_AS_our_Setup(SM2_AS_our_PP &pp)
{ 
    EC_POINT_copy(pp.g, generator); 

//    #ifdef DEBUG
//    cout << "generate the public parameters for SM2_AS_our Signature >>>" << endl; 
//    SM2_AS_our_PP_print(pp); 
//    #endif
}

/* KeyGen algorithm */ 
void SM2_AS_our_KeyGen(SM2_AS_our_PP &pp, SM2_AS_our_KP &keypair)
{ 
    BN_random(keypair.sk); // sk \sample Z_p
    EC_POINT_mul(group, keypair.pk, keypair.sk, NULL, NULL, bn_ctx); // pk = g^sk  

//    #ifdef DEBUG
//    cout << "key generation finished >>>" << endl;  
//    SM2_AS_our_KP_print(keypair); 
//    #endif
}


void IY_Gen(SM2_AS_our_PP &pp, EC_POINT *&pk, BIGNUM *&sk, IY &statwit)
{
    BN_random(statwit.y); // y \sample Z_p

    EC_POINT_add(group, statwit.Y, pp.g, pk, bn_ctx);//Y=G+X

    EC_POINT_mul(group, statwit.Y, NULL, statwit.Y, statwit.y, bn_ctx); // Y = y(G+X)
}


/* This function takes as input a message, returns a signature. */
void SM2_AS_our_Sign(SM2_AS_our_PP &pp, BIGNUM *&sk, EC_POINT *&Y, string &message, SM2_AS_our_SIG &SIG)
{
    SM2_AS_our_SIG sig; // define the signature
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

    
    EC_POINT *K1_Z = EC_POINT_new(group);
    EC_POINT_add(group, K1_Z, K1, Y, bn_ctx);        // K1_Z =kG+Y=(k+y(x+1))G

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

  
//    #ifdef DEBUG
//        cout << "SM2_AS_our signature generation finishes >>>" << endl;
//        SM2_AS_our_SIG_print(SIG);  
//    #endif

}


/* This function verifies the signature is valid for the message "msg_file" */

bool SM2_AS_our_Verify(SM2_AS_our_PP &pp, EC_POINT *&pk, EC_POINT *&Y, string &message, SM2_AS_our_SIG &SIG)
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
    EC_POINT_add(group, RIGHT, RIGHT, Y, bn_ctx);        // RIGHT = RIGHT+Y=(z+r)X+zG+Y
//RIGHT=kG+Z=kG+(x+1)Y

    //check f(K2)=f(SIG.Z)=r=f(kY)?
    BIGNUM *rrr_x = BN_new();
    BIGNUM *rrr_y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, RIGHT, rrr_x, rrr_y, bn_ctx);
    BIGNUM *rrr_x_m = BN_new();
    BN_mod_add(rrr_x_m,rrr_x,e,order,bn_ctx);//rrr_x_m=rrr_x+m


/*    if(BN_cmp(rrr_x_m,SIG.r)==0){
        Validity = true; 
    }
    else Validity = false; 
 
   #ifdef DEBUG
   if (Validity)
   {
       cout << "Signature is Valid >>>" << endl;
   }
   else
   {
       cout << "Signature is Invalid >>>" << endl;
   }
   #endif*/


    BN_free(e); 
    BN_free(rrr_x);
    BN_free(rrr_y);
    EC_POINT_free(LEFT);
    EC_POINT_free(RIGHT);  

    return Validity;
    }


