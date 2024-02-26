use std::net::UdpSocket;
use std::mem::ManuallyDrop;
use std::thread;
use std::mem::size_of;
use std::mem::transmute;
use std::collections::HashMap;

const THREADS:usize = 8;

type Buffer = [u8;0xFFFF];

//0x0001 -> 0x0100 on LE system, stays same on BE system
const fn mk_native_be_u16(num:u16) -> u16{
    unsafe{transmute::<[u8;2], u16>(
        [(num / 0x100) as u8, (num % 0x100) as u8]
    )}
}

const dns_A:u16 = mk_native_be_u16(1);
const dns_AAAA:u16 = mk_native_be_u16(28);


fn main() -> std::io::Result<()> {

    let master_socket = UdpSocket::bind("127.53.53.53:53")?;
    // let master_socket = UdpSocket::bind("::1:53")?;
    let mut threads:Vec<thread::JoinHandle<Result<(), std::io::Error>>> = vec!();


    //TODO: This should be parsed from stdin (or config file)
    let mut dns_A_table:ReverseLookupName = HashMap::new();
    dns_A_table.insert(vec!("localhost".to_string()), vec!(b"\x7F\x00\x00\x01".to_vec()));
    dns_A_table.insert(vec!("test".to_string(), "local".to_string()), vec!(b"\x01\x01\x01\x01".to_vec(),b"\x01\x01\x01\x02".to_vec()));
    let dns_A_table = dns_A_table;

    let mut lookup_table:LookupTable = HashMap::new();
    lookup_table.insert(dns_A, dns_A_table);
    let lookup_table:LookupTable = lookup_table;
    /////////////////////////////////////////////////////////
    
    //craate threads and start them
    for _ in 0..THREADS{
        let socket = master_socket.try_clone().unwrap();
        let lt = lookup_table.clone();

        let thread = thread::spawn (move || -> std::io::Result<()> {
            
            let mut buffer:Buffer = [0u8;0xFFFF];
            loop{
                let (mut size, src) = socket.recv_from(&mut buffer)?;
                handle(&lt, &mut buffer, &mut size);
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
    let mut name:Vec<String> = vec!();

    loop{
        let len:usize = header.body[index] as usize;
        if (len==0) {index += 1; break};
        name.push( String::from_utf8(header.body[index+1..index+len+1].to_vec()).unwrap() );
        index += len+1;
    }

    //now lookup the answer
    let dns_type:[u8;2] = [header.body[index], header.body[index+1]];

    let m = match(lookup.get( unsafe{transmute::<&[u8;2], &u16>(&dns_type)} )){
        Some(typed_lookup) => typed_lookup.get(&name),
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
        [header.a.high, header.a.low] = (answers.len() as u16).to_be_bytes();

        //adjust size of packet to send back
        *size += offset;

    }else{ //no match

        //set last 4 bits to 0011 (No such name NXdomain)
        header.flags[1] |= 0x03;  //we are answering
        header.flags[1] &= (!0x0c);  //we are answering

    }
    header.flags[0] |= 0x80;  //we are answering

}

struct U16be{
    high:u8,
    low:u8,
}

type LookupTable = HashMap<u16, ReverseLookupName>;
type ReverseLookupName = HashMap<Vec<String>, Vec<Vec<u8>>>;

// struct TypeAnswer


impl U16be{
    fn get(&self) -> u16{
        return (self.high as u16) <<8 | self.low as u16;
    }
}

struct Flags{
    bytes: [u8;2]
}

struct Header{
    trans_id: U16be,
    flags: [u8;2],
    q: U16be,
    a: U16be,
    auth_rr: U16be,
    add_rr:  U16be,
    body: [u8;0xFFFF-12]
}

union HeaderCast{
    raw: Buffer,
    header: ManuallyDrop<Header>,
}