import matplotlib.pyplot as plt

attributes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50] #number of attributes

# keygen
RC24 = [45.50929000000001,98.33176,138.55791,182.75826,227.10933,271.26977,316.7731,355.17669,399.47626,443.48796000000004,490.1099300000001,530.12777,571.55395,613.2885100000001,657.2231599999999,705.2388800000001,752.23686,790.15216,836.9456200000001,873.8624400000001,916.8491300000002,960.2737200000001,1008.45286,1060.47107,1097.60856,1139.26851,1181.18221,1223.07045,1273.98911,1331.83593,1376.7696600000002,1402.00969,1444.7602499999998,1480.4652099999998,1526.6309499999998,1563.0555100000001,1618.15437,1658.69544,1688.5743000000002,1742.0748499999997,1782.0501799999997,1833.2556100000002,1873.1386300000001,1908.85144,1948.5815199999997,2004.67442,2037.79196,2090.02971,2127.01667,2172.14934] 
HW14 = [36.71475,70.56284000000001,99.24727,127.22486999999998,155.42121,191.31635999999997,225.39434,253.20008,278.99698,306.00009,340.93450999999993,374.48760000000004,389.38032000000004,420.9561099999999,448.88028999999995,480.05942000000005,525.72194,544.92068,569.0852600000001,595.62886,627.1524999999999,656.5146,685.46925,723.5402299999998,762.11873,771.0415899999999,804.02756,834.5289700000001,861.5895,888.9510899999999,936.1062600000001,960.1985100000002,981.3802,1013.2085199999999,1037.25749,1067.72491,1097.6828799999998,1151.87817,1163.06573,1178.45128,1213.29693,1246.2261300000002,1275.63601,1298.78277,1328.8057800000001,1390.2489300000002,1389.3250799999998,1412.3608499999998,1447.59974,1481.44381]
LW14 = [109.39634000000001,152.26907999999997,186.30131,232.76288,241.99493,287.73681999999997,350.48584,381.66155000000003,422.6997399999999,465.89310000000006,512.3205,605.7745200000002,657.5211999999999,673.4003700000001,692.08369,728.77244,746.00174,857.4912900000002,859.2884600000001,944.98964,987.29199,983.8804,1072.39038,1043.3027699999998,1131.0520199999999,1197.6373400000002,1203.66834,1299.8901300000002,1339.9663300000002,1462.5727099999997,1360.53869,1563.90329,1574.97211,1532.71821,1654.14924,1720.79999,1701.81161,1683.8949400000001,1820.83652,1803.58053,1893.8487099999998,1865.50809,1947.6852800000001,1990.27779,2059.98388,2013.4590899999998,2131.4728800000003,2169.73031,2218.74327,2310.69267]
fig = plt.figure()


plt.plot(attributes, RC24, color='orange', linewidth=2, marker='.', label='RC24')
plt.plot(attributes, HW14, color='blue', linewidth=2, marker='.', linestyle='--', label='HW14')
plt.plot(attributes, LW14, color='purple', linewidth=2, marker='.', linestyle='--', label='LW14')

plt.legend(loc = 'upper left')
plt.xlabel('Number of Attributes')
plt.ylabel('Time Cost(ms)')

plt.savefig('encrypt.png')
plt.show()
