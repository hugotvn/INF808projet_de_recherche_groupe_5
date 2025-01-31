from collections import OrderedDict


def _recreate_dict(obj, prop, rest, val):
    prop = prop.strip("'")
    thing = obj.get(prop)
    if not thing:
        thing = {}
        obj[prop] = thing
    first, _, rest = rest.partition('.')
    if not rest:
        thing[first.strip("'")] = val
    else:
        _recreate_dict(thing, first, rest, val)


def _make_stix20_obs(store, ods, objects):
    """
    ods: group of observed-data SDOs
    objects: output OrderedDict of "results"
    """
    ph = store.placeholder
    ids = [obs['id'] for obs in ods if obs]

    # Need to complete each observation
    for obs in ods:
        # Last group could be padded with Nones?
        if not obs:
            break
        new_obs = {
            'type': 'observed-data',
        }
        for k, v in obs.items():
            if v is None:
                continue
            if ':' in k:
                continue
            if '.' in k:
                prop, _, rest = k.partition('.')
                _recreate_dict(new_obs, prop, rest, v)
            else:
                new_obs[k] = v
        objects[new_obs['id']] = new_obs

    scos = {}  # Map of SCO id to SCO object
    object_refs = {}  # Map of observation to list of contained SCO ids
    types = store.types()
    for table in types:
        if table in ['identity', 'observed-data']:
            continue
        id_set = ','.join([ph] * len(ids))
        qry = f'select sco.*, c.source_ref from "{table}" sco join __contains c on sco.id = c.target_ref and c.source_ref IN ({id_set})'
        results = []  #await store.fetch(qry, *ids)  #FIXME
        for result in results:
            sid = result['id']
            sco = {'type': table}
            for key, value in result.items():
                if key == 'id':
                    continue
                if key == 'source_ref':
                    if result[key] in object_refs:
                        object_refs[result[key]].append(sid)
                    else:
                        object_refs.update({result[key]: [sid]})
                    continue
                if value is None:
                    continue  # Ignore empty/missing properties
                if key.startswith('x_'):
                    ###_, meta = dbcache.column_metadata(table, key)
                    #TODO: look up original "longname" of column
                    key = meta['path']
                if isinstance(value, str) and value.startswith('['):
                    value = safe_loads(value)
                if '.' in key:
                    prop, _, sub = key.partition('.')
                    _recreate_dict(sco, prop, sub, value)  # {sub: value}
                else:
                    sco[key] = value

            scos[sid] = sco

    # Fetch reflists
    phs = ','.join([ph] * len(scos))  # FIXME: need to do these in batches too?
    results = []
    if phs:  # If empty, probably an error somewhere?
        try:
            qry = f"select * from __reflist where source_ref in ({phs})"
            results = await store.fetch(qry, *scos.keys())
        except UnknownViewname:
            pass
    for result in results:
        target_ref = result['target_ref']
        if target_ref not in scos:
            # Not sure about this.  The thinking here is that some
            # SCOs appear in multiple observation, but sometimes with
            # different relations.  We want to attempt to match the
            # original observations.
            continue
        sid = result['source_ref']
        ref_name = result['ref_name']
        sco = scos[sid]
        if ref_name not in sco:
            sco[ref_name] = [target_ref]
        elif target_ref not in sco[ref_name]:
            sco[ref_name].append(target_ref)

    # Add scos to observations
    for oid in ids:
        obs = objects[oid]
        if 'objects' not in obs:
            obs['objects'] = {}
        these_scos = object_refs.get(oid, [])
        sco_map = {}  # Map of SCO id to objects index
        tmp_objects = {}
        for i, s in enumerate(these_scos):
            sco_map[s] = str(i)  # Store index mapping
            tmp_objects[str(i)] = scos[s]
            obs['objects'][str(i)] = {}  # Insert blank object

        # Rewrite refs from SCO ids to objects index
        for i, sco in tmp_objects.items():
            final_sco = obs['objects'][str(i)]
            for prop, val in sco.items():
                if prop.endswith('_ref'):
                    if val in sco_map:
                        final_sco[prop] = sco_map[val]
                elif prop.endswith('_refs'):
                    reflist = [sco_map[ref] for ref in val if ref in sco_map]
                    if reflist:
                        final_sco[prop] = reflist
                else:
                    final_sco[prop] = val
