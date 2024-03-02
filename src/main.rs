use std::net::UdpSocket;
use std::mem::ManuallyDrop;
use std::thread;
use std::mem::size_of;
use std::mem::transmute;
use std::collections::HashMap;
use std::io;
use std::io::Read;
use std::time;

type Buffer = [u8;0xFFFF];

//0x0001 -> 0x0100 on LE system, stays same on BE system
const fn mk_native_be_u16(num:u16) -> u16{
    unsafe{transmute::<[u8;2], u16>(
        [(num / 0x100) as u8, (num % 0x100) as u8]
    )}
}

const dns_A:u16 = mk_native_be_u16(1);
const dns_AAAA:u16 = mk_native_be_u16(28);


/*
    Wireformat (read form stdin by default)
    Major:1 Minor:1 (0 values are used for testing only)
    Supplies config settings and DNS records to serve

    Read chunks of 1kb bytes (all values are Big endian if applicable)
    0x000 QWORD: DNSTREAM
    0x008 QWORD: Length of the section in chunks (should be \x0000000000000001 )
    0x010 DWORD: major version number (if this matches, with the baked in number you can parse it)
    0x018 DWORD: minor version number (this number can increase for non breaking changes)
    .... Reserved: all reserved bytes should be 0x00
    0x3F8 DWORD: Number of dns records to follow

    //and every record comes in 1kb chunks also

    0x000 QWORD: RECORD\x00\x00
    0x008 QWORD: Length of the section in chunks (should be \x0000000000000001 )
    0x010 DWORD: major version number (if this matches, with the baked in number you can parse it)
    0x018 DWORD: minor version number (this number can increase for non breaking changes)
    .... Reserved: all reserved bytes should be 0x00
    //next to bytes could be seen as word containing length, but ony as long as 00 byte stays reserved, which I wont guarantee

    0x0F4 DWORD: dns record TTL
    0x0F8 WORD:  dns class; will be \x00\x01  in 99% of all cases
    0x0FA WORD:  dns type in big endian (eg; A =\x0001 AAAA=\x001c etc)

    0x0FC BYTE:  reserved at \x00
    0x0FD BYTE:  length of data in 0x400
    0x0FE WORD:  length of data in 0x800

    0x100: Dns domain name wire format
    0x1FF: Reserved

    0x200: DNS record data
*/

#[derive(Debug)]
#[repr(C)]
struct HeaderChunk{
    signature:u64,
    section_chunk_length:U64be,
    version_major:U32be,
    version_minor:U32be,
    reserved:[u8;992],
    num_records:U64be,
}

#[derive(Debug)]
#[repr(C)]
struct RecordChunk{
    signature:u64,
    section_chunk_length:U64be,
    version_major:U32be,
    version_minor:U32be,
    reserved:[u8;220],

    dns_ttl: u32,
    dns_class: u16,
    dns_type: u16,

    reserved_b:u8,
    wire_domain_len:u8,
    data_len: U16be,

    wire_domain:[u8;0x100],
    data:[u8;0x200],
}

impl RecordChunk{
    fn get_wire_domain(&self) -> &[u8]{
        &self.wire_domain[0..usize::from(self.wire_domain_len)] 
    }

    fn get_data(&self) -> &[u8]{
        &self.data[0..usize::from(self.data_len.get())] 
    }    
}


fn parse_records<'a>() -> Result<LookupTable<'a>, &'static str>{

    // return Ok(lookup_table)
    let mut stdin = io::stdin().lock();
    let mut chunk = [0u8;1024];
    stdin.read(&mut chunk[..]);
    
    let header = unsafe{transmute::<&[u8;0x400], &HeaderChunk>(&chunk)};

    
    //TODO: checking other fields, and see if they are ok
    //TODO: use ttl form config file instead of 300

    let num_records = header.num_records.get();
    let mut lookup_table:LookupTable = HashMap::new();

    for record_number in 0..num_records{

        let mut chunk = [0u8;1024];
        stdin.read(&mut chunk[..]);
        let record = unsafe{transmute::<&[u8;0x400], &RecordChunk>(&chunk)};

        let wire_domain = record.get_wire_domain();

        // table domain -> array of answer data
        let mut table: &mut HashMap< Vec<u8>, Vec<Vec<u8>> > = match lookup_table.get_mut(&record.dns_type){
            Some(x) => x,
            None => {
                lookup_table.insert(record.dns_type, HashMap::new());
                lookup_table.get_mut(&record.dns_type).unwrap()
            }
        };

        let mut data: &mut Vec<Vec<u8>> = match table.get_mut(wire_domain){
            Some(x) => x,
            None => {
                table.insert(wire_domain.to_vec(), vec!());
                table.get_mut(wire_domain).unwrap()
            }
        };

        data.push(record.get_data().to_vec());
    }

    Ok(lookup_table)
}

#[derive(Debug)]
#[repr(C)]
struct U16be{
    bytes: [u8;2]
}
impl U16be{
    fn get(&self) -> u16{
        u16::from_be_bytes(self.bytes)
    }
    fn put(&mut self, value:u16){
        self.bytes = value.to_be_bytes();
    }
}

#[derive(Debug)]
#[repr(C)]
struct U32be{
    bytes: [u8;4]
}
impl U32be{
    fn get(&self) -> u32{
        u32::from_be_bytes(self.bytes)
    }
}

#[derive(Debug)]
#[repr(C)]
struct U64be{
    bytes: [u8;8]
}
impl U64be{
    fn get(&self) -> u64{
        u64::from_be_bytes(self.bytes)
    }
}


fn main() -> std::io::Result<()> {

    // println!("{:?}", size_of::<HeaderChunk>());
    // println!("{:?}", size_of::<RecordChunk>());
    // println!("{:?}", size_of::<[u8;0x400]>());
    
    let master_socket = UdpSocket::bind("127.53.53.53:53")?;
    let num_threads:u16 = 8;
    // let master_socket = UdpSocket::bind("::1:53")?;
    let mut threads:Vec<thread::JoinHandle<Result<(), std::io::Error>>> = vec!();
    let lookup_table:LookupTable = parse_records().expect("Could not parse configuration");

    //craate threads and start them
    for _ in 0u16..num_threads{
        let socket = master_socket.try_clone().unwrap();
        let lt = lookup_table.clone();

        let thread = thread::spawn (move || -> std::io::Result<()> {
            
            let mut buffer:Buffer = [0u8;0xFFFF];
            loop{
                let (mut size, src) = socket.recv_from(&mut buffer)?;
                handle(&lt, &mut buffer, &mut size);
                // std::thread::sleep(time::Duration::from_millis(10));
                socket.send_to(&buffer[0..size], &src).unwrap();                
            }

        });

        threads.push(thread);
    }

    threads.into_iter().map(|t| t.join()).collect::<Vec<_>>();
    Ok(())
}


//just blast your answer in this buffer
fn handle(lookup: &LookupTable, buffer:&mut Buffer, size:&mut usize){

    let header:&mut Header = unsafe{transmute::<&mut Buffer, &mut Header>(buffer)};

    let mut index:usize = 0;
    // let mut name:Vec<String> = vec!();

    loop{
        let len:usize = header.body[index] as usize;
        if (len==0) {index += 1; break};
        index += len+1;
    }
    let wire_domain = &header.body[0..index];

    // println!("domain | {:?}", wire_domain );

    //now lookup the answer
    let dns_type:[u8;2] = [header.body[index], header.body[index+1]];

    let m = match(lookup.get( unsafe{transmute::<&[u8;2], &u16>(&dns_type)} )){
        Some(typed_lookup) => typed_lookup.get(wire_domain),
        None => None,
    };

    index += 4; //seek over type and class field

    if let Some(data) = m{ //if we found a match

        //produce answers
        let mut answers:Vec<Vec<u8>> = vec!();
        for record in data{

            let mut answer:Vec<u8> = vec!(0xc0,0x0c); //points to queried name

            //type
            answer.push(dns_type[0]);
            answer.push(dns_type[1]);

            //class
            answer.push(0x00);
            answer.push(0x01);

            //TTL (5 mins)
            answer.push(0x00);
            answer.push(0x00);
            answer.push(0x01);
            answer.push(0x2c);

            //specific answer type
            let len:[u8;2] = (record.len() as u16).to_be_bytes();
            answer.push(len[0]);
            answer.push(len[1]);

            //data record
            for byte in record{
                answer.push(*byte);
            }

            answers.push(answer);
        }

        // move stuff downward to make space for answers
        let offset:usize = answers.iter().map(|a| a.len()).sum();
        for i in (index..*size).rev(){
            header.body[i+offset] = header.body[i];
        }

        //copy answer into packet
        for answer in &answers{
            header.body[(index)..(index+answer.len())].copy_from_slice(&answer);
            index += answer.len();
        }

        //set anmount of answers
        header.a.put(answers.len() as u16);

        //adjust size of packet to send back
        *size += offset;

    }else{ //no match

        //set last 4 bits to 0011 (No such name NXdomain)
        header.flags[1] |= 0x03;  //we are answering
        header.flags[1] &= !0x0c;  //we are answering

    }
    header.flags[0] |= 0x80;  //we are answering
    header.flags[0] |= 0x04;  //server is authoritive
    header.flags[1] &= 0x7F;  //server does not do recursion


}

type LookupTable<'a> = HashMap<u16, ReverseLookupName<'a>>;
type ReverseLookupName<'a> = HashMap<Vec<u8>, Vec<Vec<u8>>>;


#[repr(C)]
struct Flags{
    bytes: [u8;2]
}

#[repr(C)]
struct Header{
    trans_id: U16be,
    flags: [u8;2],
    q: U16be,
    a: U16be,
    auth_rr: U16be,
    add_rr:  U16be,
    body: [u8;0xFFFF-12]
}

#[repr(C)]
union HeaderCast{
    raw: Buffer,
    header: ManuallyDrop<Header>,
}