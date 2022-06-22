/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8> TYPE_TCP = 6;
const bit<8> TYPE_UDP = 17;


/* Table Sizes */

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<17>  identification;
    bit<2>   flags;//
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<6>  res;
    bit<6>  flags;//
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}



/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
	
    ethernet_h      ethernet;
    ipv4_h          ipv4;
    tcp_t           tcp;
	udp_t           udp;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
	
    bit<8>          threshold_flag;
    bit<16>         prev_node_id;
    bit<8>          class_id;
	bit<6>          flag;//
    bit<16>         src_port;
    bit<16>         dst_port;
}


    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in                         pkt,
                     /* User */    
                     out my_ingress_headers_t          hdr,
                     out my_ingress_metadata_t         meta,
                     /* Intrinsic */
                     out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
   
   
     state start {
        pkt.extract(ig_intr_md);
        // advance: move forward the pointer
        pkt.advance(PORT_METADATA_SIZE);
        meta = {0, 0, 0, 0, 0, 0};
        transition port_ayalse;
    }
    
    state port_ayalse {
        transition select(ig_intr_md.ingress_port) {
            default: parse_ethernet;
        }
    }
    
	

   
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            default: reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            default: reject;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
		meta.flag=hdr.tcp.flags;
        meta.src_port = hdr.tcp.srcPort;
        meta.dst_port = hdr.tcp.dstPort;
        transition accept;
    }
	
	state parse_udp {
        pkt.extract(hdr.udp);
		meta.flag=0;
        meta.src_port = hdr.udp.srcPort;
        meta.dst_port = hdr.udp.dstPort;
        transition accept;
    }
}



control Level(inout my_ingress_headers_t hdr,
              inout my_ingress_metadata_t meta,
              inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
              (bit<16> node_size)
{
    action CheckFeature(bit<16> node_id, bit<8> less_than_feature) {
        meta.prev_node_id = node_id;                       
        meta.threshold_flag = less_than_feature; 
		//meta.flag=2;		
    }                                                           

    action SetClass(bit<16> node_id, bit<8> class_id) {
         meta.class_id = class_id;
         meta.prev_node_id = node_id;
         ig_tm_md.ucast_egress_port = (bit<9>)class_id; // for debug
		  
         //hdr.extra_info.setInvalid();
		 //meta.flag=1;
         exit;
     }
     
    table node {
          key = {
            meta.prev_node_id: exact;
            meta.threshold_flag: exact;
            // features, range
            // hdr.ipv4.ihl:ternary;
            // hdr.ipv4.diffserv:ternary;
	    hdr.ipv4.flags:range;  //DF+MF
	    hdr.ipv4.ihl:range;
	    //hdr.ipv4.ihl:range;
            hdr.ipv4.protocol:range;
            // 1 bit ternary?
            // hdr.ipv4.flags[0:0]:ternary; //Preserve
            // hdr.ipv4.flags[2:2]:ternary;  //MF
            // hdr.ipv4.ihl:ternary;
	    meta.flag:range;  // SYN
	    hdr.ipv4.diffserv:range;
            hdr.ipv4.ttl:range;
            //meta.srcPort:ternary;
            //meta.dstPort:ternary;
            //meta.flag[2:2]:ternary;  // RST
            // meta.flag[0:0]:;  // FIN
         }
         actions = {CheckFeature; SetClass;}
         size = node_size;
     }
       
    apply {node.apply();}
}

    /***************** M A T C H - A C T I O N  *********************/

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{

   //Level(1+2+8+30+84+198) level0; 
  
		Level(600)level0;
  
		Level(600)level1;
  
		Level(600)level2;
  
		Level(600)level3;
  
		Level(600)level4;
  
		Level(600)level5;
  
		Level(600)level6;
  
		Level(600)level7;
  
		//Level(500)level8;
  
		// Level(4050)level9;
        
        action drop_(){
            ig_dprsr_md.drop_ctl = 0x1;
            exit;
        }

        action set_detected(){
            exit;
        }
        table filter_list{
            key = {
                hdr.ipv4.src_addr: exact;
                hdr.ipv4.dst_addr: exact;
                hdr.ipv4.protocol: exact;
                meta.src_port: exact;
                meta.dst_port: exact;
            }
            actions = {drop_; set_detected; NoAction;}
            default_action = NoAction;
        }
  
  
    apply {
		filter_list.apply();
        
		level0.apply(hdr,meta,ig_tm_md);
		
		level1.apply(hdr,meta,ig_tm_md);
		
		level2.apply(hdr,meta,ig_tm_md);
		
		level3.apply(hdr,meta,ig_tm_md);
		
		level4.apply(hdr,meta,ig_tm_md);
		
		level5.apply(hdr,meta,ig_tm_md);
		
		level6.apply(hdr,meta,ig_tm_md);
		
		level7.apply(hdr,meta,ig_tm_md);
		
		//level8.apply(hdr,meta,ig_tm_md);
		
		// level9.apply(hdr,meta,ig_tm_md);
		
		// ig_tm_md.bypass_egress = 1;
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
	
    apply {
		
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
