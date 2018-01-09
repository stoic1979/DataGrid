window.addEventListener('load', initMap);

function initMap() {
  var map = new OpenLayers.Map('Map', {
    controls: [new OpenLayers.Control.Navigation(),
               new OpenLayers.Control.PanZoomBar(),
               new OpenLayers.Control.Attribution(),
               new OpenLayers.Control.ScaleLine(),
               new OpenLayers.Control.LayerSwitcher()],
  });

  var osm = new OpenLayers.Layer.OSM();
  var toMercator = OpenLayers.Projection.transforms['EPSG:4326']['EPSG:3857'];
  var center = toMercator({x:-0.05,y:51.5});
  var mappingLayer   = new OpenLayers.Layer.OSM("USA Map");
  var fromProjection = new OpenLayers.Projection("EPSG:4326");
  var toProjection   = new OpenLayers.Projection("EPSG:900913");
  var position       = new OpenLayers.LonLat(mapConfig.clon,mapConfig.clat).transform(fromProjection, toProjection);
  var zoom           = 5;
  map.addLayer(mappingLayer);
  map.setCenter(position, zoom);

  var dict = {COAL: "#000000",OIL: "#8B4513", GAS:"#FF0000", NUCLEAR: "#800080", BIOMASS:"#80FFFF", HYDRO: "#0000FF", SOLAR: "#FFFF00", WIND: "#00FF00", OTHF:"#008000"};

  var features = [];
  for (var i=0;i<mapConfig.plants.length;i++) {
    let lat = mapConfig.plants[i]['lat'];
    let lon = mapConfig.plants[i]['lon'];
    features.push(new OpenLayers.Feature.Vector(toMercator(new OpenLayers.Geometry.Point(lon,lat)),
    {
        Name :  mapConfig.plants[i]['na'],
        Fuel :  mapConfig.plants[i]['fuel'],
        Code :  mapConfig.plants[i]['oc'],
        Oper :  mapConfig.plants[i]['op'],
        Nerc :  mapConfig.plants[i]['ne'],
        Cnty :  mapConfig.plants[i]['cn'],
        Nblr :  mapConfig.plants[i]['nblr'],
        Ngen :  mapConfig.plants[i]['ngen'],
        Npca :  mapConfig.plants[i]['npc']
    }, {
        fillColor : dict[mapConfig.plants[i]['fuel']],
        fillOpacity : 0.8,
        strokeColor : "#ee9900",
        strokeOpacity : 0.5,
        strokeWidth : 1,
        pointRadius : 10
    }));
  }

  // create the layer with listeners to create and destroy popups *
  var vector = new OpenLayers.Layer.Vector("Power Plants",{
      eventListeners:{
          featureselected:function(evt){
              var feature = evt.feature;
              var popup = new OpenLayers.Popup.FramedCloud("popup",
              OpenLayers.LonLat.fromString(feature.geometry.toShortString()),
              null,"<div>"
              +"<b>Plant Name: </b> "    + feature.attributes.Name + "</div>"
              +"<b>Fuel Category: </b> " + feature.attributes.Fuel + "</div>"
              +"<br><b>Operator: </b> " + feature.attributes.Oper + "</div>"
              +"<br><b>NERC region: </b>"+ feature.attributes.Nerc + "</div>"
              +"<br><b>County Name: </b>"+ feature.attributes.Cnty + "</div>"
              +"<br><b>Nameplate Capacity: </b> " + feature.attributes.Npca + " MW</div>"
              ,null,
              true
              );
              feature.popup = popup;
              map.addPopup(popup);
          },
          'featureunselected':function(evt){
              var feature = evt.feature;
              map.removePopup(feature.popup);
              feature.popup.destroy();
              feature.popup = null;
          }
      }
  });

  vector.addFeatures(features);
  var selector = new OpenLayers.Control.SelectFeature(vector,{
    //hover: true,
    autoActivate:true
  });
  map.addLayers([mappingLayer, vector]);
  map.addControl(selector);
  map.setCenter(position);
  map.zoomToExtent(new OpenLayers.Bounds(mapConfig.minLng,mapConfig.minLat,mapConfig.maxLng,mapConfig.maxLat).transform("EPSG:4326", "EPSG:900913"));
}
