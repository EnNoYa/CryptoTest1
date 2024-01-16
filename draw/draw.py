import matplotlib.pyplot as plt

ue = [1, 10, 50, 100, 1000, 5000] #number of users
thiswork = [1, 2,  3, 4, 5, 6] #
ni = [5, 10, 20, 35, 45]
fig = plt.figure()

plt.plot(ue, thiswork, color='orange', linewidth=2, marker='.', label='thiswork')
# plt.plot(ue, ni, color='blue', linewidth=2, marker='.', linestyle='--', label='Ni.')

plt.legend(loc = 'upper left')
plt.xlabel('Number of Users')
plt.ylabel('Time Cost(ms)')

#plt.savifg('time cost.png')
plt.show()