with open('data.json', 'w') as f:
    f.write('''{
    \t"name":"Someone", 
    \t"number": 123,
    ''')

    for i in range(1000000):
        f.write(f'\t"test{i}":"{i}{i}{i}{i}{i}",\n')

    f.write('\t"last":"nothing"\n}\n')
